/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/test_runner.h
 *
 * Minimal single-header test framework. Each TEST_CASE is registered at
 * static-init time; test_main.cpp calls run_all() which executes them and
 * returns the failure count (0 = success).
 */
#pragma once

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace nullbot::test {

inline std::vector<std::pair<std::string, std::function<void()>>>& registry() {
    static std::vector<std::pair<std::string, std::function<void()>>> r;
    return r;
}

struct TestRegistrar {
    TestRegistrar(const char* name, std::function<void()> fn) {
        registry().emplace_back(name, std::move(fn));
    }
};

inline int run_all() {
    int failed = 0;
    for (const auto& [name, fn] : registry()) {
        try {
            fn();
            std::cout << "[PASS] " << name << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[FAIL] " << name << " : " << e.what() << "\n";
            ++failed;
        }
    }
    const auto total = static_cast<int>(registry().size());
    std::cout << "\n" << (total - failed) << "/" << total << " tests passed.\n";
    return failed;
}

} // namespace nullbot::test

#define TEST_CASE(name)                                                    \
    static void NULLBOT_TEST_BODY_##name();                                \
    static ::nullbot::test::TestRegistrar NULLBOT_REGISTRAR_##name{       \
        #name, NULLBOT_TEST_BODY_##name};                                  \
    static void NULLBOT_TEST_BODY_##name()

#define REQUIRE(expr)                                                      \
    do {                                                                   \
        if (!(expr))                                                       \
            throw std::runtime_error("REQUIRE(" #expr ") failed at line " \
                                     + std::to_string(__LINE__));          \
    } while (false)

#define REQUIRE_FALSE(expr) REQUIRE(!(expr))
