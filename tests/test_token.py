"""Token (Fernet-like) conformance tests.

Tests token encryption, decryption, and HMAC verification by comparing
SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_token_encrypt_decrypt(sut, reference):
    key = random_hex(64)  # 32B signing + 32B encryption
    plaintext = random_hex(48)
    iv = random_hex(16)
    ref = reference.execute("token_encrypt", key=key, plaintext=plaintext, iv=iv)
    res = sut.execute("token_encrypt", key=key, plaintext=plaintext, iv=iv)
    assert_hex_equal(res["token"], ref["token"])
    # Decrypt with both
    ref_dec = reference.execute("token_decrypt", key=key, token=ref["token"])
    res_dec = sut.execute("token_decrypt", key=key, token=ref["token"])
    assert_hex_equal(ref_dec["plaintext"], plaintext)
    assert_hex_equal(res_dec["plaintext"], plaintext)


def test_token_verify_hmac(sut, reference):
    key = random_hex(64)
    plaintext = random_hex(32)
    iv = random_hex(16)
    ref = reference.execute("token_encrypt", key=key, plaintext=plaintext, iv=iv)
    ref_v = reference.execute("token_verify_hmac", key=key, token=ref["token"])
    res_v = sut.execute("token_verify_hmac", key=key, token=ref["token"])
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


def test_token_cross_decrypt(sut, reference):
    """Encrypt with SUT, decrypt with reference and vice versa."""
    key = random_hex(64)
    plaintext = random_hex(100)
    # SUT encrypt -> reference decrypt
    res_enc = sut.execute("token_encrypt", key=key, plaintext=plaintext)
    ref_dec = reference.execute("token_decrypt", key=key, token=res_enc["token"])
    assert_hex_equal(ref_dec["plaintext"], plaintext)
    # Reference encrypt -> SUT decrypt
    ref_enc = reference.execute("token_encrypt", key=key, plaintext=plaintext)
    res_dec = sut.execute("token_decrypt", key=key, token=ref_enc["token"])
    assert_hex_equal(res_dec["plaintext"], plaintext)
