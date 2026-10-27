"""Aux zone tests: add, probe, delete."""

REQUIRES = "any"  # test block: isoc | gnu-linux | any
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--yes", "--no-admin"]

def test_add_probe_del(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=hello", "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    assert "Aux entry" in so or "Found 1" in so, f"probe: {so[:200]}"
    assert_success(["Aux", device, "--aux-del", "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    assert "No aux entries" in so or "Found 0" in so, f"probe after del: {so[:200]}"

def test_wrong_key(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=secret", "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    # Wrong unlock key should error
    assert_error(["Aux", device, "--aux-probe", "--key=456", "--max-unlock-time=3", "--no-admin"], binary)

def test_probe_exec(binary, device):
    """--aux-probe executes SHELL entries only with --aux-exec."""
    outfile = "/tmp/windham_aux_probe_exec"
    if os.path.exists(outfile):
        os.remove(outfile)
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add-command=echo probe_ran > " + outfile,
                    "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    # without --aux-exec: listed, not executed
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "SHELL" in so, f"probe: {so[:200]}"
    assert not os.path.exists(outfile), "SHELL command ran without --aux-exec"
    # with --aux-exec: printed first, then executed
    so, _ = assert_success(["Aux", device, "--aux-probe", "--aux-exec", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "exec:" in so, f"probe exec output: {so[:300]}"
    assert os.path.exists(outfile), "SHELL command did not run with --aux-exec"
    os.remove(outfile)

def test_public_entry_master_key(binary, device):
    """Entries added with --master-key are public: visible to every probe."""
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=private_note", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    so, _ = assert_success(["Open", device, "--key=123", "--max-unlock-time=3",
                            "--show-master-key", "--no-admin"], binary)
    master_key = so.strip()
    assert len(master_key) == 95, f"unexpected master key format: {master_key!r}"
    assert_success(["Aux", device, f"--master-key={master_key}", "--aux-add=public_note",
                    "--max-unlock-time=3", "--no-admin"], binary)
    # master-key probe: the public entry only
    so, _ = assert_success(["Aux", device, f"--master-key={master_key}", "--aux-probe",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "public_note" in so and "public" in so, f"master probe: {so[:300]}"
    assert "private_note" not in so, "key-encrypted entry leaked into master probe"
    # normal-key probe: the key entry plus the public entry
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "private_note" in so and "public_note" in so, f"key probe: {so[:300]}"

def test_delkey_cleans_aux(binary, device):
    """DelKey removes the aux entries bound to the deleted key's keyslot."""
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=doomed", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    assert_success(["AddKey", device, "--key=123", "--new-key=456", "--target-time=0.1",
                    "--max-unlock-time=3", "--no-admin"], binary)
    assert_success(["DelKey", device, "--key=123", "--max-unlock-time=3",
                    "--no-admin", "--yes"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=456",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "doomed" not in so, f"aux entry survived DelKey: {so[:300]}"

def test_link_entry_lifecycle(binary, device):
    """LINK_OPEN entries can be added, listed, and deleted (no cascade on ISOC)."""
    link_target = device + ".link"
    create_test_device(device)
    create_test_device(link_target)
    assert_success(_new(device), binary)
    assert_success(["New", link_target, "--target-level=3", "--key=456",
                    "--target-time=0.1", "--yes", "--no-admin"], binary)
    assert_success(["Aux", device, "--aux-add-link", link_target, "--aux-target-key=456",
                    "--key=123", "--max-unlock-time=3", "--no-admin"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "LINK_OPEN" in so, f"probe: {so[:300]}"
    assert_success(["Aux", device, "--aux-del", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "LINK_OPEN" not in so, f"link entry survived del: {so[:300]}"
    os.remove(link_target)

def test_aux_rm_single_entry(binary, device):
    """--aux-rm=<index> deletes one probed entry, leaving the rest."""
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(["Aux", device, "--aux-add=keep_me", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    assert_success(["Aux", device, "--aux-add=drop_me", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    assert_success(["Aux", device, "--aux-rm=2", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "keep_me" in so, f"remaining entry missing: {so[:300]}"
    assert "drop_me" not in so, f"removed entry still probed: {so[:300]}"
