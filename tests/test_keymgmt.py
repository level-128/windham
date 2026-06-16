"""Key management: AddKey, DelKey, rapid-add, duplicate rejection."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--key=123", "--target-time=0.1", "--yes", "--no-admin", "--allow-swap"]
def _open(device, key="123"): return ["Open", device, f"--key={key}", "--max-unlock-time=1", "--dry-run", "--no-admin", "--allow-swap"]

def test_rapid_add(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--rapid-add", "--generate-random-key",
                    "--no-admin", "--allow-swap"], binary)
    assert_success(_open(device), binary)

def test_header_transform_add(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--generate-random-key",
                    "--no-admin", "--allow-swap"], binary)
    assert_success(_open(device), binary)

def test_del_key(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--rapid-add", "--generate-random-key",
                    "--no-admin", "--allow-swap"], binary)
    # AddKey added a random key. Unlock key (123) still works.
    assert_success(_open(device), binary)
    # Delete the unlock key 123. Random key remains.
    assert_success(["DelKey", device, "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap", "--yes"], binary)
    # Unlock with key=123 should now fail
    assert_error(_open(device), binary)
