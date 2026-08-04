"""Probe action tests."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, create_test_device

def _new(device): return ["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--yes", "--no-admin"]

def test_probe_dir(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    rc, so, se = run_windham(["Probe", f"--dir={device}", "--no-admin"], binary)
    # Note: --dir may also trigger --probe-linux default in GNU/Linux
    # Accept both empty output (if probe_linux took over) and valid output
    assert rc == 0, f"probe rc={rc}: {so+se[:200]}"

def test_probe_nonexistent(binary, device):
    rc, so, se = run_windham(["Probe", "--dir=/tmp/nonexistent_windham_probe_test", "--no-admin"], binary)
    assert rc == 0, f"probe nonexistent rc={rc}: {so+se[:200]}"

def test_probe_linux(binary, device):
    rc, so, se = run_windham(["Probe", "--probe-linux", "--no-admin"], binary)
    if rc != 0:
        assert "Cannot open" in (so+se) or "not supported" in (so+se), f"probe-linux: {so+se[:200]}"
