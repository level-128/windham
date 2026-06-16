"""Aux zone variants: --aux-type, --no-aux."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

_FLAGS = ["--yes", "--no-admin", "--allow-swap"]
_NEW  = lambda d: ["New", d, "--key=123", "--target-time=0.1"] + _FLAGS

def test_aux_with_type(binary, device):
    """Add aux entry with --aux-type."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Aux", device, "--aux-add=typed_content", "--aux-type=mytype",
                    "--key=123", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    assert "Aux entry" in so or "Found" in so, f"probe: {so[:200]}"

def test_open_no_aux(binary, device):
    """Open with --no-aux should still work normally."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Aux", device, "--aux-add=secret", "--key=123",
                    "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    assert_success(["Open", device, "--key=123", "--max-unlock-time=1", "--dry-run",
                    "--no-aux", "--no-admin", "--allow-swap"], binary)
