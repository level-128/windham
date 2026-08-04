"""Suspend and Resume tests."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--yes", "--no-admin"]

def test_suspend_resume(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Suspend", device, "--key=123", "--no-admin"], binary)
    assert_error(["Suspend", device, "--key=123", "--no-admin"], binary)
    assert_success(["Open", device, "--key=123", "--max-unlock-time=1", "--dry-run", "--no-admin"], binary)
    assert_success(["Resume", device, "--key=123", "--no-admin"], binary)
    assert_success(["Open", device, "--key=123", "--max-unlock-time=1", "--dry-run", "--no-admin"], binary)
