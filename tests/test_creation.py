"""Basic device creation, open, and close tests."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--yes", "--no-admin"]
def _open(device, key="123"): return ["Open", device, f"--key={key}", "--max-unlock-time=1", "--dry-run", "--no-admin"]

def test_new(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)

def test_open_dry_run(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(_open(device), binary)

def test_wrong_password(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_error(_open(device, key="wrong"), binary)
