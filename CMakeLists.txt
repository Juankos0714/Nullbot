cmake_minimum_required(VERSION 3.25)
project(NullBot VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── Output directories ───────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ─── Platform check ───────────────────────────────────────────────────────────
if(NOT WIN32)
    message(FATAL_ERROR "NullBot is Windows-only.")
endif()

# ─── Find dependencies ────────────────────────────────────────────────────────

# YARA (build from source or use vcpkg)
find_package(yara CONFIG QUIET)
if(NOT yara_FOUND)
    message(WARNING "libyara not found via find_package. Set YARA_INCLUDE_DIR and YARA_LIBRARY manually.")
    set(YARA_INCLUDE_DIR "" CACHE PATH "Path to YARA include dir")
    set(YARA_LIBRARY     "" CACHE FILEPATH "Path to YARA library")
endif()

# SQLite (bundled)
add_library(sqlite3 STATIC
    third_party/sqlite3/sqlite3.c
)
target_include_directories(sqlite3 PUBLIC third_party/sqlite3)

# ─── Core engine library ──────────────────────────────────────────────────────
add_library(nullbot_core STATIC
    core/scanner/scanner.cpp
    core/heuristic/pe_analyzer.cpp
    core/quarantine/quarantine.cpp
    signatures/sig_database.cpp
)

target_include_directories(nullbot_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${YARA_INCLUDE_DIR}
)

target_link_libraries(nullbot_core
    PUBLIC
        sqlite3
        ${YARA_LIBRARY}
        crypt32
        ws2_32
        advapi32
        shlwapi
)

# ─── Network module library ───────────────────────────────────────────────────
add_library(nullbot_network STATIC
    network/c2_detection/c2_detector.cpp
    network/dga/dga_detector.cpp
    network/monitor/net_monitor.cpp
)

target_include_directories(nullbot_network
    PUBLIC ${CMAKE_SOURCE_DIR}
)

target_link_libraries(nullbot_network
    PUBLIC
        nullbot_core
        ws2_32
        iphlpapi
)

# ─── CLI executable ───────────────────────────────────────────────────────────
add_executable(nullbot_cli
    main.cpp
)

target_link_libraries(nullbot_cli
    PRIVATE
        nullbot_core
        nullbot_network
)

# ─── Compiler flags ───────────────────────────────────────────────────────────
target_compile_options(nullbot_core PRIVATE
    /W4       # High warning level
    /WX       # Warnings as errors
    /GS       # Buffer security check
    /DYNAMICBASE  # ASLR
    /NXCOMPAT     # DEP
)

target_compile_definitions(nullbot_core PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00  # Windows 10/11
)

# ─── Tests ────────────────────────────────────────────────────────────────────
enable_testing()

add_executable(nullbot_tests
    tests/unit/test_scanner.cpp
    tests/unit/test_dga.cpp
    tests/unit/test_heuristic.cpp
    tests/integration/test_quarantine.cpp
)

target_link_libraries(nullbot_tests
    PRIVATE
        nullbot_core
        nullbot_network
)

add_test(NAME UnitTests COMMAND nullbot_tests)

# ─── Install ──────────────────────────────────────────────────────────────────
install(TARGETS nullbot_cli
    RUNTIME DESTINATION bin
)

install(DIRECTORY signatures/rules/
    DESTINATION data/rules
    FILES_MATCHING PATTERN "*.yar"
)
