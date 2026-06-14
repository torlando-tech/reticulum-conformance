// Destination + name-hash commands. Pure SHA-256 truncations plus the
// deterministic Destination lifecycle ops (construct / name split / expand /
// GROUP encrypt / proof-strategy validation).
//
// These mirror RNS.Destination (RNS 1.3.1) semantics exactly, but are
// reimplemented over RNS::Cryptography + the bridge Token helpers rather than
// instantiating a full RNS::Destination object — the real constructor calls
// Transport::register_destination(), which needs a running Reticulum instance.
// Every byte-producing path reuses the same primitives the conformance suite
// already proves byte-equivalent (sha256, X25519/Ed25519 derive, the modified
// Fernet Token used for GROUP keys).

#include "../bridge.h"

#include "Bytes.h"
#include "Type.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/X25519.h"
#include "Cryptography/Ed25519.h"

#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace TD = RNS::Type::Destination;

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

bridge::Bytes truncated_sha256_str(const std::string& s, size_t bytes) {
    bridge::Bytes data(s.begin(), s.end());
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + bytes);
}

bridge::Bytes truncated_sha256(const bridge::Bytes& data, size_t bytes) {
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + bytes);
}

// aspects can arrive as a JSON list of strings or a comma-separated string.
std::vector<std::string> parse_aspects(const bridge::json& p) {
    std::vector<std::string> aspects;
    if (p.contains("aspects") && !p["aspects"].is_null()) {
        const auto& a = p["aspects"];
        if (a.is_array()) {
            for (const auto& item : a) aspects.push_back(item.get<std::string>());
        } else if (a.is_string()) {
            std::string s = a.get<std::string>();
            if (!s.empty()) {
                size_t start = 0, comma;
                while ((comma = s.find(',', start)) != std::string::npos) {
                    aspects.push_back(s.substr(start, comma - start));
                    start = comma + 1;
                }
                aspects.push_back(s.substr(start));
            }
        }
    }
    return aspects;
}

// expand_name(None, app, *aspects) — dotted join, no identity suffix.
std::string join_name(const std::string& app, const std::vector<std::string>& aspects) {
    std::string name = app;
    for (const auto& asp : aspects) {
        name += ".";
        name += asp;
    }
    return name;
}

// RNS.Destination.types == [SINGLE,GROUP,PLAIN,LINK]. Accepts either a spec
// name ("single"/"group"/"plain"/"link") or a raw integer. Raises ValueError
// ("Unknown destination type") for anything outside the set — matching
// Destination.__init__'s guard ordering (type is validated before direction).
int resolve_type(const bridge::json& p) {
    if (!p.contains("type") || p["type"].is_null()) {
        throw std::runtime_error("Missing param: type");
    }
    const auto& t = p["type"];
    int v;
    if (t.is_string()) {
        std::string s = t.get<std::string>();
        for (auto& c : s) c = (char)std::tolower((unsigned char)c);
        if (s == "single")      v = TD::SINGLE;
        else if (s == "group")  v = TD::GROUP;
        else if (s == "plain")  v = TD::PLAIN;
        else if (s == "link")   v = TD::LINK;
        else throw std::runtime_error("Unknown destination type");
    } else {
        v = t.get<int>();
    }
    if (v != TD::SINGLE && v != TD::GROUP && v != TD::PLAIN && v != TD::LINK) {
        throw std::runtime_error("Unknown destination type");
    }
    return v;
}

// RNS.Destination.directions == [IN, OUT]. Accepts "in"/"out" or a raw int.
int resolve_direction(const bridge::json& p) {
    if (!p.contains("direction") || p["direction"].is_null()) {
        throw std::runtime_error("Missing param: direction");
    }
    const auto& d = p["direction"];
    int v;
    if (d.is_string()) {
        std::string s = d.get<std::string>();
        for (auto& c : s) c = (char)std::tolower((unsigned char)c);
        if (s == "in")       v = TD::IN;
        else if (s == "out") v = TD::OUT;
        else throw std::runtime_error("Unknown destination direction");
    } else {
        v = d.get<int>();
    }
    if (v != TD::IN && v != TD::OUT) {
        throw std::runtime_error("Unknown destination direction");
    }
    return v;
}

struct IdentityInfo {
    bridge::Bytes hash;     // truncated_sha256(public_key, 16)
    std::string hexhash;    // hash.hex()
};

// Reticulum identity = X25519(32) || Ed25519(32) private; public key is the
// concatenation of the two public keys; identity hash is the 16-byte truncated
// SHA-256 of that public key.
IdentityInfo derive_identity(const bridge::Bytes& priv64) {
    if (priv64.size() != 64) {
        throw std::runtime_error("identity private_key must be 64 bytes");
    }
    bridge::Bytes x25519_priv(priv64.begin(), priv64.begin() + 32);
    bridge::Bytes ed25519_priv(priv64.begin() + 32, priv64.end());

    auto x = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x25519_priv));
    auto x_pub = from_rns(x->public_key()->public_bytes());
    auto e = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed25519_priv));
    auto e_pub = from_rns(e->public_key()->public_bytes());

    bridge::Bytes public_key;
    public_key.insert(public_key.end(), x_pub.begin(), x_pub.end());
    public_key.insert(public_key.end(), e_pub.begin(), e_pub.end());

    IdentityInfo info;
    info.hash = truncated_sha256(public_key, 16);
    info.hexhash = bridge::to_hex(info.hash);
    return info;
}

// RNS.Identity() — fresh random keypair. A random 64-byte seed fed through the
// same derivation yields a valid, unique identity (the hexhash is all the
// caller can observe / anchor on).
IdentityInfo random_identity() {
    return derive_identity(bridge::random_bytes(64));
}

// Destination.hash(identity, app, *aspects): full_hash(name_hash || id.hash)[:16],
// where the GROUP/PLAIN (no-identity) case folds in only the name_hash.
bridge::Bytes destination_address(const bridge::Bytes& name_hash,
                                  const bridge::Bytes* identity_hash) {
    bridge::Bytes material = name_hash;
    if (identity_hash != nullptr) {
        material.insert(material.end(), identity_hash->begin(), identity_hash->end());
    }
    return truncated_sha256(material, 16);
}

}  // namespace

REGISTER_COMMAND(name_hash, {
    auto name = bridge::str_param(p, "name");
    auto hash = truncated_sha256_str(name, 10);   // 10 bytes per Reticulum spec
    return bridge::json{{"hash", bridge::to_hex(hash)}};
})

REGISTER_COMMAND(destination_hash, {
    auto identity_hash = bridge::hex_param(p, "identity_hash");
    auto app_name = bridge::str_param(p, "app_name");

    auto aspects = parse_aspects(p);
    std::string full_name = join_name(app_name, aspects);

    auto name_hash = truncated_sha256_str(full_name, 10);
    auto dest_hash = destination_address(name_hash, &identity_hash);

    return bridge::json{
        {"name_hash", bridge::to_hex(name_hash)},
        {"destination_hash", bridge::to_hex(dest_hash)},
        {"full_name", full_name},
    };
})

// Destination.__init__ (RNS.Destination, 1.3.1). Validates type/direction,
// applies the IN-auto-identity / OUT-requires-identity / PLAIN-no-identity
// guards, and reports the constructed type/direction/proof_strategy + name,
// name_hash and destination_hash. The auto-generated identity's hexhash is
// surfaced so the suite can re-derive the name_hash preimage independently.
REGISTER_COMMAND(destination_construct, {
    int type = resolve_type(p);             // validated before direction (spec order)
    int direction = resolve_direction(p);
    auto app_name = bridge::str_param(p, "app_name");
    if (app_name.find('.') != std::string::npos) {
        throw std::runtime_error("Dots can't be used in app names");
    }
    auto aspects = parse_aspects(p);

    bool have_identity = false;
    bool auto_generated = false;
    IdentityInfo ident;

    if (p.contains("identity_private_key") && !p["identity_private_key"].is_null()) {
        auto priv = bridge::from_hex(p["identity_private_key"].get<std::string>());
        ident = derive_identity(priv);
        have_identity = true;
    }

    // identity == None && IN && type != PLAIN -> auto-generate, append hexhash aspect.
    if (!have_identity && direction == TD::IN && type != TD::PLAIN) {
        ident = random_identity();
        have_identity = true;
        auto_generated = true;
        aspects.push_back(ident.hexhash);
    }
    // identity == None && OUT && type != PLAIN -> rejected.
    if (!have_identity && direction == TD::OUT && type != TD::PLAIN) {
        throw std::runtime_error("Can't create outbound SINGLE destination without an identity");
    }
    // identity != None && PLAIN -> rejected.
    if (have_identity && type == TD::PLAIN) {
        throw std::runtime_error("Selected destination type PLAIN cannot hold an identity");
    }

    // name = expand_name(identity, app, *aspects): dotted join + identity suffix.
    std::string name = join_name(app_name, aspects);
    if (have_identity) {
        name += ".";
        name += ident.hexhash;
    }

    // name_hash = full_hash(expand_name(None, app, *aspects))[:10] — no suffix.
    std::string name_for_hash = join_name(app_name, aspects);
    auto name_hash = truncated_sha256_str(name_for_hash, 10);
    auto dest_hash = destination_address(name_hash, have_identity ? &ident.hash : nullptr);

    bridge::json r{
        {"type", type},
        {"direction", direction},
        {"proof_strategy", TD::PROVE_NONE},   // Destination.__init__ default 0x21
        {"name", name},
        {"name_hash", bridge::to_hex(name_hash)},
        {"destination_hash", bridge::to_hex(dest_hash)},
        {"hexhash", bridge::to_hex(dest_hash)},
    };
    if (auto_generated) {
        r["auto_identity_hexhash"] = ident.hexhash;
    }
    return r;
})

// Destination.app_and_aspects_from_name(full_name): split on '.', first
// component is the app name, the rest are the aspects.
REGISTER_COMMAND(app_and_aspects_from_name, {
    auto full = bridge::str_param(p, "full_name");
    std::vector<std::string> components;
    size_t start = 0, dot;
    while ((dot = full.find('.', start)) != std::string::npos) {
        components.push_back(full.substr(start, dot - start));
        start = dot + 1;
    }
    components.push_back(full.substr(start));

    std::string app_name = components.empty() ? "" : components[0];
    std::vector<std::string> aspects(components.begin() + (components.empty() ? 0 : 1),
                                     components.end());
    return bridge::json{
        {"app_name", app_name},
        {"aspects", aspects},
    };
})

// Destination.hash_from_name_and_identity(full_name, identity): the full name
// IS expand_name(None, app, *aspects), so name_hash = full_hash(full)[:10],
// then the 16-byte address folds in the identity hash.
REGISTER_COMMAND(hash_from_name_and_identity, {
    auto full = bridge::str_param(p, "full_name");
    auto identity_hash = bridge::hex_param(p, "identity_hash");

    auto name_hash = truncated_sha256_str(full, 10);
    auto dest_hash = destination_address(name_hash, &identity_hash);
    return bridge::json{
        {"name_hash", bridge::to_hex(name_hash)},
        {"destination_hash", bridge::to_hex(dest_hash)},
    };
})

// Destination.expand_name(identity, app, *aspects): dotted app/aspects join,
// with '.' + identity.hexhash appended iff an identity is supplied.
REGISTER_COMMAND(destination_expand_name, {
    auto app_name = bridge::str_param(p, "app_name");
    if (app_name.find('.') != std::string::npos) {
        throw std::runtime_error("Dots can't be used in app names");
    }
    auto aspects = parse_aspects(p);
    std::string name = join_name(app_name, aspects);

    if (p.contains("identity_private_key") && !p["identity_private_key"].is_null()) {
        auto priv = bridge::from_hex(p["identity_private_key"].get<std::string>());
        auto ident = derive_identity(priv);
        name += ".";
        name += ident.hexhash;
    }
    return bridge::json{{"name", name}};
})

// Destination.set_proof_strategy(strategy): accepts only the values in
// proof_strategies == [PROVE_NONE,PROVE_APP,PROVE_ALL]; anything else raises
// TypeError("Unsupported proof strategy").
REGISTER_COMMAND(destination_set_proof_strategy_raw, {
    // Resolve+validate the destination's type/direction first (mirrors
    // construct-then-set_proof_strategy); the negative case is the strategy.
    (void)resolve_type(p);
    (void)resolve_direction(p);
    int strategy = bridge::int_param(p, "strategy_value");
    if (strategy != TD::PROVE_NONE && strategy != TD::PROVE_APP && strategy != TD::PROVE_ALL) {
        throw std::runtime_error("Unsupported proof strategy");
    }
    return bridge::json{{"proof_strategy", strategy}};
})

// Destination.encrypt GROUP path: requires a symmetric Token key from
// create_keys()/load_private_key(); without one RNS raises ValueError. The
// GROUP key is a 64-byte AES-256-CBC Token key (Token.generate_key()).
REGISTER_COMMAND(destination_group_encrypt, {
    (void)bridge::str_param(p, "app_name");   // GROUP destinations still carry a name
    auto plaintext = bridge::hex_param(p, "plaintext");

    bridge::Bytes key64;
    if (p.contains("key") && !p["key"].is_null()) {
        key64 = bridge::from_hex(p["key"].get<std::string>());
        if (key64.size() != 64) {
            throw std::runtime_error("GROUP key must be 64 bytes");
        }
    } else if (p.contains("create_keys") && p["create_keys"].is_boolean() &&
               p["create_keys"].get<bool>()) {
        key64 = bridge::random_bytes(64);     // Token.generate_key(AES_256_CBC)
    } else {
        throw std::runtime_error(
            "No private key held by GROUP destination. Did you create or load one?");
    }

    auto iv = bridge::random_bytes(16);
    auto token = bridge::token_seal(key64, plaintext, iv);
    auto roundtrip = bridge::token_open(key64, token);

    return bridge::json{
        {"has_key", true},
        {"ciphertext", bridge::to_hex(token)},
        {"roundtrip", bridge::to_hex(roundtrip)},
    };
})
