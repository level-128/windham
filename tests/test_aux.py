"""Aux zone tests: add, probe, delete."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--key=123", "--target-time=0.1", "--yes", "--no-admin", "--allow-swap"]

def test_add_probe_del(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=hello", "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    assert "Aux entry" in so or "Found 1" in so, f"probe: {so[:200]}"
    assert_success(["Aux", device, "--aux-del", "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    assert "No aux entries" in so or "Found 0" in so, f"probe after del: {so[:200]}"

def test_wrong_key(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=secret", "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    # Wrong unlock key should error
    assert_error(["Aux", device, "--aux-probe", "--key=456", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
