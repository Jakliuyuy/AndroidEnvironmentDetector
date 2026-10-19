#!/usr/bin/env bash
# ==============================================================================
# E2E Test Suite Runner for Android Environment Security Detection App
# Supported Tiers:
#   Tier 1: Feature Coverage (F01-F20, 100 tests)
#   Tier 2: Boundary & Corner Cases (F01-F20, 100 tests)
#   Tier 3: Cross-Feature Pairwise Combinations (20 tests)
#   Tier 4: Real-World Threat Scenarios (S1-S5, 5 tests)
# Total Test Suite: 225 Test Cases
# ==============================================================================

set -o pipefail

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_RED="\033[31m"
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_BLUE="\033[34m"
CLR_CYAN="\033[36m"
CLR_WHITE="\033[37m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TESTS_DIR="${PROJECT_ROOT}/tests"

print_banner() {
    echo -e "${CLR_CYAN}${CLR_BOLD}"
    echo "=============================================================================="
    echo "       ANDROID ENVIRONMENT SECURITY DETECTION — E2E TEST RUNNER"
    echo "=============================================================================="
    echo -e "${CLR_RESET}"
}

print_usage() {
    echo -e "${CLR_BOLD}Usage:${CLR_RESET} $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all             Run all test tiers (Tiers 1-4, 225 test cases) [Default]"
    echo "  --tier <1|2|3|4>  Run a specific test tier only"
    echo "  --summary         Print test inventory without running"
    echo "  -v, --verbose     Verbose pytest execution output"
    echo "  -h, --help        Show this help message and exit"
    echo ""
}

TARGET_TIER="all"
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            TARGET_TIER="all"
            shift
            ;;
        --tier)
            TARGET_TIER="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        --summary)
            TARGET_TIER="summary_only"
            shift
            ;;
        -h|--help)
            print_banner
            print_usage
            exit 0
            ;;
        *)
            echo -e "${CLR_RED}Unknown option: $1${CLR_RESET}"
            print_usage
            exit 1
            ;;
    esac
done

print_banner

echo -e "${CLR_BOLD}Environment Information:${CLR_RESET}"
echo -e "  Project Root: ${CLR_BLUE}${PROJECT_ROOT}${CLR_RESET}"
echo -e "  Python:       $(python3 --version 2>&1)"
echo -e "  Pytest:       $(pytest --version 2>&1 | head -n 1)"
echo ""

print_inventory_table() {
    echo -e "${CLR_BOLD}Test Suite Inventory Matrix:${CLR_RESET}"
    echo -e "+-------+---------------------------------------+-------------+------------+"
    echo -e "| Tier  | Focus Area                            | Test Scope  | Test Count |"
    echo -e "+-------+---------------------------------------+-------------+------------+"
    echo -e "| T1    | Feature Coverage (F01-F20)            | Baseline    | 100 tests  |"
    echo -e "| T2    | Boundary & Corner Cases (F01-F20)     | Edge & Stress| 100 tests |"
    echo -e "| T3    | Cross-Feature Combinations            | Pairwise    |  20 tests  |"
    echo -e "| T4    | Real-World Threat Scenarios (S1-S5)   | End-to-End  |   5 tests  |"
    echo -e "+-------+---------------------------------------+-------------+------------+"
    echo -e "| TOTAL | Full Requirements Verification        | Complete    | 225 tests  |"
    echo -e "+-------+---------------------------------------+-------------+------------+"
    echo ""
}

if [[ "${TARGET_TIER}" == "summary_only" ]]; then
    print_inventory_table
    exit 0
fi

# Determine target path for pytest
case "${TARGET_TIER}" in
    "1")
        TEST_TARGET="${TESTS_DIR}/tier1_features"
        TIER_LABEL="Tier 1: Feature Coverage (F01-F20)"
        ;;
    "2")
        TEST_TARGET="${TESTS_DIR}/tier2_boundaries"
        TIER_LABEL="Tier 2: Boundary & Corner Cases (F01-F20)"
        ;;
    "3")
        TEST_TARGET="${TESTS_DIR}/tier3_combinations"
        TIER_LABEL="Tier 3: Cross-Feature Combinations"
        ;;
    "4")
        TEST_TARGET="${TESTS_DIR}/tier4_scenarios"
        TIER_LABEL="Tier 4: Real-World Threat Scenarios (S1-S5)"
        ;;
    "all")
        TEST_TARGET="${TESTS_DIR}"
        TIER_LABEL="All Tiers (Tiers 1-4, 225 test cases)"
        ;;
    *)
        echo -e "${CLR_RED}Invalid tier specified: ${TARGET_TIER}. Choose from 1, 2, 3, 4, or all.${CLR_RESET}"
        exit 1
        ;;
esac

echo -e "${CLR_BOLD}Executing:${CLR_RESET} ${CLR_CYAN}${TIER_LABEL}${CLR_RESET}"
echo -e "${CLR_BOLD}Command:${CLR_RESET}   pytest ${TEST_TARGET} ${VERBOSE:-"--tb=short"}"
echo ""

START_TIME=$(date +%s%N)
pytest "${TEST_TARGET}" ${VERBOSE:-"--tb=short"}
EXIT_CODE=$?
END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo ""
echo -e "------------------------------------------------------------------------------"
if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo -e "${CLR_GREEN}${CLR_BOLD}[SUCCESS] ALL TESTS PASSED!${CLR_RESET} (Duration: ${DURATION_MS} ms)"
    print_inventory_table
    echo -e "${CLR_GREEN}E2E Test Suite Status: VERIFIED & READY FOR TEST_READY.md${CLR_RESET}"
    exit 0
else
    echo -e "${CLR_RED}${CLR_BOLD}[FAILURE] TEST RUN ENCOUNTERED FAILURES.${CLR_RESET} (Exit Code: ${EXIT_CODE})"
    echo -e "${CLR_YELLOW}Inspect the traceback details above to escalate/fix issues.${CLR_RESET}"
    exit ${EXIT_CODE}
fi
