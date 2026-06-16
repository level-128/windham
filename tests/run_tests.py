#!/usr/bin/env python3
"""Windham test runner.

Usage:
    python3 tests/run_tests.py [--binary path/to/windham] [--device /path/to/tmpfile]
                               [--verbose] [test_name ...]
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import traceback
import importlib
import shutil

IS_ROOT = os.geteuid() == 0
SKIP_ROOT_MSG = "(skipped: requires root)"

from tests.utils import TestFailure

TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BINARY = os.path.join(os.path.dirname(TESTS_DIR), "cmake-build-debug", "windham_debug")
DEFAULT_DEVICE = "/tmp/windham_testfile"


def run_tests(binary, device, test_filter=None, verbose=False):
    """Discover and run all test functions."""
    tests = []

    for fname in sorted(os.listdir(TESTS_DIR)):
        if fname.startswith("test_") and fname.endswith(".py") and fname != "test_runner.py":
            modname = fname[:-3]
            try:
                mod = importlib.import_module(f"tests.{modname}")
            except Exception as e:
                print(f"  skip {modname}: {type(e).__name__}: {e}")
                continue
            for attr in dir(mod):
                if attr.startswith("test_"):
                    func = getattr(mod, attr)
                    if callable(func):
                        if not test_filter or any(t in attr for t in test_filter):
                            tests.append((f"{modname}.{attr}", func))

    if not tests:
        print("No tests found.")
        return True

    passed = 0
    failed = 0
    for name, func in tests:
        print(f"  {name}...", end=" ", flush=True)
        try:
            func(binary, device)
            print("OK")
            passed += 1
        except TestFailure as e:
            print(f"FAIL\n    {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR")
            if verbose:
                traceback.print_exc()
            else:
                print(f"    {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


IS_ROOT = os.geteuid() == 0


def elevate():
    """Re-execute self via pkexec to gain root privileges."""
    if IS_ROOT:
        return
    if not shutil.which("pkexec"):
        print("WARNING: pkexec not found. Some tests may fail without root.")
        return
    args = [sys.executable] + sys.argv
    print("Elevating via pkexec...")
    os.execvp("pkexec", ["pkexec"] + args)


def main():
    parser = argparse.ArgumentParser(description="Windham test runner")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="Path to windham binary")
    parser.add_argument("--device", default=DEFAULT_DEVICE, help="Temporary device file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--no-elevate", action="store_true", help="Skip pkexec elevation")
    parser.add_argument("test_filter", nargs="*", help="Test name filter(s)")
    args = parser.parse_args()

    if not args.no_elevate:
        elevate()

    if not os.path.exists(args.binary):
        print(f"ERROR: binary not found: {args.binary}")
        sys.exit(1)

    if os.path.exists(args.device):
        os.remove(args.device)

    ok = run_tests(args.binary, args.device, args.test_filter, args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
