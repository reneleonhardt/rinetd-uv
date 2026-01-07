#!/usr/bin/env python3
"""
Test rinetd-uv include directive functionality.

This test validates:
- Basic single file includes
- Wildcard pattern includes
- Nested includes (recursive)
- Circular include detection
- Maximum depth limit
- Relative path resolution
- No files match pattern (warning)
"""

import subprocess
import sys
import os
import tempfile

# Path to rinetd-uv binary
RINETD_BIN = "./src/rinetd-uv"

# Test results
tests_run = 0
tests_passed = 0
tests_failed = 0

def run_test(name, config_file, should_succeed=True, expected_error=None):
    """Run a single test case.

    Args:
        name: Test name
        config_file: Path to config file
        should_succeed: True if config should parse successfully
        expected_error: If should_succeed=False, string that should appear in error output
    """
    global tests_run, tests_passed, tests_failed
    tests_run += 1

    print(f"\n{'='*60}")
    print(f"Test {tests_run}: {name}")
    print(f"{'='*60}")
    print(f"Config: {config_file}")
    print(f"Expected: {'SUCCESS' if should_succeed else 'FAILURE'}")

    # Strategy: Start rinetd-uv with config
    # - If it starts successfully (config valid), it will keep running → we kill it after short delay
    # - If config is invalid, it will exit immediately with error
    # We use Popen for better process control

    cmd = [RINETD_BIN, "-c", config_file, "-f"]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Wait up to 1 second for process to exit (happens if config invalid)
        stdout, stderr = proc.communicate(timeout=1.0)
        # Process exited - parsing failed
        actual_success = False
        output = stderr + stdout
    except subprocess.TimeoutExpired:
        # Process still running after 1 second - parsing succeeded
        actual_success = True
        # Kill the process
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=2.0)
            output = stderr + stdout
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            output = stderr + stdout

    print(f"Actual: {'SUCCESS' if actual_success else 'FAILURE'}")

    if output:
        print(f"\nOutput:\n{output}")

    # Check result
    success = (actual_success == should_succeed)

    if not should_succeed and expected_error:
        # For failure cases, also check error message
        if expected_error not in output:
            print(f"\n❌ FAIL: Expected error message not found: '{expected_error}'")
            success = False

    if success:
        print(f"\n✓ PASS")
        tests_passed += 1
    else:
        print(f"\n✗ FAIL")
        tests_failed += 1

    return success


def main():
    """Run all test cases."""
    print("="*60)
    print("rinetd-uv Include Directive Test Suite")
    print("="*60)

    # Check if binary exists
    if not os.path.exists(RINETD_BIN):
        print(f"Error: Binary not found at {RINETD_BIN}")
        print("Please run 'make' first to build rinetd-uv")
        return 1

    # Test 1: Basic single file include
    run_test(
        "Basic single file include",
        "test/fixtures/includes/main-basic.conf",
        should_succeed=True
    )

    # Test 2: Wildcard pattern include
    run_test(
        "Wildcard pattern include",
        "test/fixtures/includes/main-wildcard.conf",
        should_succeed=True
    )

    # Test 3: Nested includes (3 levels: A→B→C)
    run_test(
        "Nested includes",
        "test/fixtures/includes/nested-1.conf",
        should_succeed=True
    )

    # Test 4: Circular include detection (A→B→A)
    run_test(
        "Circular include detection",
        "test/fixtures/includes/circular-a.conf",
        should_succeed=False,
        expected_error="circular include detected"
    )

    # Test 5: Maximum depth limit (11 levels, max is 10)
    run_test(
        "Maximum depth limit",
        "test/fixtures/includes/deep-01.conf",
        should_succeed=False,
        expected_error="maximum include depth"
    )

    # Test 6: Relative path resolution
    run_test(
        "Relative path resolution",
        "test/fixtures/includes/relative/parent.conf",
        should_succeed=True
    )

    # Test 7: No files match pattern (should warn but continue)
    run_test(
        "No files match pattern (warning)",
        "test/fixtures/includes/nomatch.conf",
        should_succeed=True
    )

    # Print summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total tests: {tests_run}")
    print(f"Passed: {tests_passed}")
    print(f"Failed: {tests_failed}")
    print(f"Success rate: {tests_passed/tests_run*100:.1f}%")

    return 0 if tests_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
