"""Shared test utilities."""
import subprocess, os

SIZE_MB = 8  # 8 MB disk file for tests

class TestFailure(Exception):
    pass

def run_windham(args, binary, stdin_text=None, timeout=30):
    cmd = [binary] + args
    result = subprocess.run(cmd, capture_output=True, text=True, input=stdin_text, timeout=timeout)
    return result.returncode, result.stdout, result.stderr

def assert_success(args, binary, stdin_text=None, msg="", timeout=30):
    rc, so, se = run_windham(args, binary, stdin_text=stdin_text, timeout=timeout)
    if rc != 0:
        raise TestFailure(f"Expected success, got rc={rc}\n  cmd: {' '.join(args)}\n  stderr: {se.strip()}\n  stdout: {so.strip()[:200]}\n  {msg}")
    return so, se

def assert_error(args, binary, stdin_text=None, msg="", timeout=30):
    rc, so, se = run_windham(args, binary, stdin_text=stdin_text, timeout=timeout)
    if rc == 0:
        raise TestFailure(f"Expected error, got rc=0\n  cmd: {' '.join(args)}\n  {msg}")
    return so, se

def create_test_device(path):
    """Create a blank file for windham to use."""
    if os.path.exists(path):
        os.remove(path)
    with open(path, "wb") as f:
        f.seek(SIZE_MB * 1024 * 1024 - 1)
        f.write(b"\0")
