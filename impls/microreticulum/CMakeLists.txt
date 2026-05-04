cmake_minimum_required(VERSION 3.14)
project(microReticulumBridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# attermann/Crypto — header + source library, the same one microReticulum
# uses for SHA/HMAC/AES/X25519/Ed25519 primitives. We wrap these through
# bridge command handlers; the conformance tests verify byte-equivalence
# with the Python reference, so using the same primitives is what we want.
FetchContent_Declare(
    crypto
    GIT_REPOSITORY https://github.com/attermann/Crypto.git
    # Pin to a specific commit rather than `master` so the build is
    # reproducible — these primitives feed crypto correctness and silently
    # picking up upstream churn would be a CI-stability and audit risk.
    # Bump deliberately when we want a newer Crypto. (Initial commit on
    # the attermann/Crypto fork, 2024-11-03.)
    GIT_TAG da68972a4badb3d403556c7c5d348f24c5acb02c
)
FetchContent_MakeAvailable(crypto)

# ArduinoJson — header-only. microReticulum's Bytes.h has a convertToJson/
# convertFromJson hook in the ArduinoJson namespace; we need the header to
# parse but never actually use the hook from the bridge.
FetchContent_Declare(
    arduinojson
    GIT_REPOSITORY https://github.com/bblanchon/ArduinoJson.git
    GIT_TAG v7.4.2
)
FetchContent_MakeAvailable(arduinojson)

file(GLOB CRYPTO_SOURCES ${crypto_SOURCE_DIR}/*.cpp)
add_library(CryptoLib STATIC ${CRYPTO_SOURCES})
target_include_directories(CryptoLib PUBLIC ${crypto_SOURCE_DIR})
target_compile_options(CryptoLib PRIVATE -Wno-everything)

# Path to microReticulum source. Defaults to the user's pyxis pinned fork —
# can be overridden with -DMICRORETICULUM_DIR=/path/to/microReticulum.
if(NOT DEFINED MICRORETICULUM_DIR)
    set(MICRORETICULUM_DIR "$ENV{HOME}/repos/pyxis/deps/microReticulum")
endif()

if(NOT EXISTS "${MICRORETICULUM_DIR}/src/Cryptography/Hashes.h")
    message(FATAL_ERROR
        "microReticulum sources not found at ${MICRORETICULUM_DIR}. "
        "Set -DMICRORETICULUM_DIR=/path/to/microReticulum.")
endif()

# Compile only the Cryptography subdirectory + Bytes from microReticulum.
# Anything that pulls in MsgPack (Link, Channel, Resource, Packet) is
# excluded — Tier 2A is stateless primitives only. Tier 2B will add the
# transport-layer pieces and need a full microReticulum build.
file(GLOB MRN_CRYPTO_SOURCES
    ${MICRORETICULUM_DIR}/src/Cryptography/*.cpp
    ${MICRORETICULUM_DIR}/src/Bytes.cpp
    ${MICRORETICULUM_DIR}/src/Log.cpp
    ${MICRORETICULUM_DIR}/src/Utilities/Crc.cpp
)
# Strip BZ2 — pulls in libbz2 and isn't needed for Phase 2A.
list(FILTER MRN_CRYPTO_SOURCES EXCLUDE REGEX "BZ2.cpp$")

add_library(MicroReticulumCryptoLib STATIC ${MRN_CRYPTO_SOURCES})
target_include_directories(MicroReticulumCryptoLib PUBLIC
    ${MICRORETICULUM_DIR}/src
    ${crypto_SOURCE_DIR}
)
# microReticulum's Bytes.h includes ArduinoJson but only uses it in member
# functions we don't call from the crypto pieces. Provide a stub so the
# header compiles. (Same trick as pyxis/tests/native/.)
target_include_directories(MicroReticulumCryptoLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/stubs)
target_compile_definitions(MicroReticulumCryptoLib PRIVATE
    NATIVE
    LIBRARY_TEST
    RNS_NO_FS
)
target_compile_options(MicroReticulumCryptoLib PRIVATE -Wno-everything)
target_link_libraries(MicroReticulumCryptoLib PUBLIC CryptoLib ArduinoJson)

# Bridge executable. CONFIGURE_DEPENDS makes CMake re-glob when files are
# added/removed without needing manual reconfigure.
file(GLOB BRIDGE_SOURCES CONFIGURE_DEPENDS src/*.cpp src/commands/*.cpp)
add_executable(microReticulumBridge ${BRIDGE_SOURCES})
target_include_directories(microReticulumBridge PRIVATE
    src
    ${MICRORETICULUM_DIR}/src
    ${crypto_SOURCE_DIR}
    stubs
)
target_link_libraries(microReticulumBridge PRIVATE
    MicroReticulumCryptoLib
    CryptoLib
    ArduinoJson
)
target_compile_options(microReticulumBridge PRIVATE
    -Wall
    -Wno-unused-parameter
    -Wno-missing-field-initializers
)
target_compile_definitions(microReticulumBridge PRIVATE NATIVE LIBRARY_TEST)
