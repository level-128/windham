#!/usr/bin/env python3
"""Windham test runner.

The suite is split into two blocks by target platform:

  isoc        ISO C baseline. Built directly with the C compiler and no
              platform defines, e.g.:
                  cc -std=c11 -O2 frontend.c -lm -o windham_isoc
              Pure userspace: operates on regular files, needs no root, and
              has no kernel device-mapper (real Opens use the no-op "print"
              driver). This is the block that must pass everywhere.

  gnu-linux   GNU/Linux CMake build exercising the kernel dm-crypt backend:
              loop devices, /dev/mapper, cascade unlock. Requires root and
              is run separately against a Debug/Test build.

Tests declare which block they belong to with a REQUIRES attribute
("isoc", "gnu-linux" or "any"): a module attribute gates a whole file, a
function attribute gates a single test. Tests that do not match the
selected platform are skipped.

Usage:
    python3 tests/run_tests.py --binary ./windham_isoc
    python3 tests/run_tests.py --binary cmake-build-debug/windham_debug
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import traceback
import importlib
import shutil
import subprocess

import tests.utils
from tests.utils import TestFailure

TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BINARY = os.path.join(os.path.dirname(TESTS_DIR), "cmake-build-debug", "windham_debug")
DEFAULT_DEVICE = "/tmp/windham_testfile"


def detect_platform(binary):
    """Return "gnu-linux" or "isoc" for the binary under test.

    CMake GNU/Linux builds embed a kernel-version banner in their help text;
    the directly compiled ISO C baseline does not. Returns None if the
    binary cannot be queried.
    """
    try:
        r = subprocess.run([binary, "Help"], capture_output=True, text=True, timeout=30)
    except OSError as e:
        print(f"ERROR: cannot run {binary}: {e}")
        return None
    if "Target Linux kernel version" in r.stdout:
        return "gnu-linux"
    return "isoc"


def _requires(func, mod):
    return getattr(func, "requires", None) or getattr(mod, "REQUIRES", "any")


def run_tests(binary, device, test_filter=None, verbose=False, platform="isoc"):
    """Discover and run all test functions."""
    # Clean up leftover dm devices from previous runs. Meaningless for the
    # ISOC baseline; failure is ignored either way.
    subprocess.run([binary, "Close", "--all", "--no-admin"],
                   capture_output=True)

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
                            tests.append((f"{modname}.{attr}", func, _requires(func, mod)))

    if not tests:
        print("No tests found.")
        return True

    passed = 0
    failed = 0
    skipped = 0
    for name, func, req in tests:
        if req != "any" and req != platform:
            print(f"  {name}... SKIP (requires {req} binary)")
            skipped += 1
            continue
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

    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
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
    parser.add_argument("--platform", choices=["auto", "isoc", "gnu-linux"], default="auto",
                        help="Target platform of the binary (default: auto-detect)")
    parser.add_argument("test_filter", nargs="*", help="Test name filter(s)")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"ERROR: binary not found: {args.binary}")
        sys.exit(1)

    if args.platform == "auto":
        args.platform = detect_platform(args.binary)
        if args.platform is None:
            sys.exit(1)
        print(f"Detected platform: {args.platform}")
    else:
        detected = detect_platform(args.binary)
        if detected and detected != args.platform:
            print(f"WARNING: binary looks like a {detected} build, "
                  f"but --platform={args.platform} was forced")

    tests.utils.PLATFORM = args.platform

    # Only the GNU/Linux block needs root (loop devices, dm-crypt, udev).
    if args.platform == "gnu-linux" and not args.no_elevate:
        elevate()

    if os.path.exists(args.device):
        os.remove(args.device)

    ok = run_tests(args.binary, args.device, args.test_filter, args.verbose, args.platform)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
