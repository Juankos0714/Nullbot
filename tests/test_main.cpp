/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/test_main.cpp
 */

#include "tests/test_runner.h"

int main() {
    return ::nullbot::test::run_all() == 0 ? 0 : 1;
}
