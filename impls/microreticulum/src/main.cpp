// JSON-RPC stdio loop for the microReticulum conformance bridge.
//
// Protocol (per reticulum-conformance bridge convention):
//   - Print exactly "READY\n" on stdout when the binary is ready
//   - Read newline-delimited JSON request lines from stdin
//   - Write newline-delimited JSON response lines to stdout
//   - One request, one response. All binary fields encoded as lowercase hex.

#include "bridge.h"

#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>

int main() {
    // Buffered stdio defeats stdout-flush-after-each-line — use unbuffered
    // C streams and let nlohmann::json write through std::cout with flush.
    std::ios::sync_with_stdio(false);
    std::cout.setf(std::ios::unitbuf);

    std::cout << "READY\n";
    std::cout.flush();

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        std::string request_id = "parse_error";
        bridge::json response;

        try {
            auto request = bridge::json::parse(line);
            request_id = request.value("id", std::string("unknown"));
            std::string command = request.at("command").get<std::string>();
            const auto& params = request.contains("params") && !request["params"].is_null()
                ? request["params"]
                : bridge::json::object();

            const auto* handler = bridge::Registry::instance().find(command);
            if (!handler) {
                throw std::runtime_error("Unknown command: " + command);
            }
            auto result = (*handler)(params);

            response = {
                {"id", request_id},
                {"success", true},
                {"result", result},
            };
        } catch (const std::exception& e) {
            response = {
                {"id", request_id},
                {"success", false},
                {"error", e.what()},
            };
        } catch (...) {
            response = {
                {"id", request_id},
                {"success", false},
                {"error", "unknown exception"},
            };
        }

        std::cout << response.dump() << "\n";
        std::cout.flush();
    }
    return 0;
}
