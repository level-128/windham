"""Suspend and Resume tests."""

REQUIRES = "any"  # test block: isoc | gnu-linux | any
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--yes", "--no-admin"]

def test_suspend_resume(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Suspend", device, "--key=123", "--no-admin"], binary)
    assert_error(["Suspend", device, "--key=123", "--no-admin"], binary)
    assert_success(["Open", device, "--key=123", "--max-unlock-time=3", "--dry-run", "--no-admin"], binary)
    assert_success(["Resume", device, "--key=123", "--no-admin"], binary)
    assert_success(["Open", device, "--key=123", "--max-unlock-time=3", "--dry-run", "--no-admin"], binary)

def test_suspended_open_without_key(binary, device):
    """A suspended device opens with no credentials at all; after Resume it must not."""
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Suspend", device, "--key=123", "--no-admin"], binary)
    # no --key/--key-file/--keystdin: closed stdin must not hang the prompt
    rc, so, se = run_windham(
        ["Open", device, "--max-unlock-time=3", "--dry-run", "--no-admin"],
        binary, stdin_text="")
    assert rc == 0, f"suspended open without key failed: {so+se[:200]}"
    assert_success(["Resume", device, "--key=123", "--no-admin"], binary)
    assert_error(
        ["Open", device, "--max-unlock-time=3", "--dry-run", "--no-admin"],
        binary, stdin_text="")
