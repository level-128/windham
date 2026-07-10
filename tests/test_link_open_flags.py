"""LINK_OPEN STOP_EXEC cascade test: verify flag-based link pruning."""
import os, sys, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import assert_success, create_test_device, TestFailure, run_windham

_FLAGS  = ["--yes", "--no-admin", "--allow-swap"]
_UNLOCK = ["--max-unlock-time=3", "--max-unlock-memory=500000"]
LOSETUP = "/usr/sbin/losetup"

def _new(device):
    return ["New", device, "--key=123", "--target-level=1", "--target-time=0.1"] + _FLAGS

def _add_link(src, dst, **kw):
    cmd = ["Aux", src, "--aux-add-link", dst, "--key=123", "--aux-target-key=123"] + _UNLOCK + _FLAGS
    if kw.get("shortcut"):
        cmd.append("--aux-link-flag=SHORTCUT")
    prio = kw.get("prio")
    if prio is not None:
        cmd.append(f"--aux-link-prio={prio}")
    return cmd

def _open(device):
    return ["Open", device, "--key=123"] + _UNLOCK + _FLAGS

def _losetup_find_free():
    return subprocess.run([LOSETUP, "-f"], capture_output=True, text=True).stdout.strip()

def _losetup_attach(filepath, loopdev):
    subprocess.run([LOSETUP, loopdev, filepath], check=True, capture_output=True)

def _losetup_detach(loopdev):
    subprocess.run([LOSETUP, "-d", loopdev], capture_output=True)

def _parse_uuid_hex(stdout):
    for line in stdout.split('\n'):
        if 'UUID:' in line:
            parts = line.strip().split()
            for p in parts:
                p = p.strip().replace('-', '')
                if len(p) == 32:
                    try:
                        int(p, 16)
                        return p
                    except ValueError:
                        pass
    return None


def test_link_open_stop_exec(binary, device):
    """
    Topology (8 devices, A B C D E F G H):
        A → B(prio=50, STOP_EXEC), C(prio=100)
        B → D(prio=50), E(prio=100)
        C → F(prio=50)
        D → G(prio=50, STOP_EXEC), H(prio=100)
        (E, F, G, H: no children)

    Expected cascade:
        Open A → A's children sorted DESC: [C(100), B(50)] → push: FIFO = [B(50,idx=1), C(100,idx=1)]
        Pop B → open B → STOP_EXEC → discard C(100,idx=1) [C pruned]
        B's children: [E(100), D(50)] → push: FIFO = [D(50,idx=2), E(100,idx=2)]
        Pop D → open D → D's children: [H(100), G(50)] → push: FIFO = [G(50,idx=3), H(100,idx=3)]
        Pop G → open G → STOP_EXEC → discard H(100,idx=3) [H pruned]
        FIFO = [E(100,idx=2)]
        Pop E → open E → done

    Opened: A, B, D, G, E  (5)
    NOT opened due to STOP_EXEC: C, F, H  (3)
    """
    N = 8
    all_disks = []
    all_loops = []

    try:
        for i in range(N):
            path = f"/tmp/wh_se_{i}"
            if os.path.exists(path):
                os.remove(path)
            create_test_device(path)
            all_disks.append(path)
            lp = _losetup_find_free()
            _losetup_attach(path, lp)
            all_loops.append(lp)

        for lp in all_loops:
            assert_success(_new(lp), binary, timeout=30)

        real_loops = all_loops

        # Build links: map[name] = (src_idx, dst_idx, prio, shortcut)
        links = [
            ("A→B", 0, 1, 50, True),
            ("A→C", 0, 2, 100, False),
            ("B→D", 1, 3, 50, False),
            ("B→E", 1, 4, 100, False),
            ("C→F", 2, 5, 50, False),
            ("D→G", 3, 6, 50, True),
            ("D→H", 3, 7, 100, False),
        ]

        for name, src, dst, prio, shortcut in links:
            cmd = _add_link(real_loops[src], real_loops[dst], prio=prio, shortcut=shortcut)
            rc, so, se = run_windham(cmd, binary, timeout=60)
            if rc != 0:
                raise TestFailure(
                    f"add-link {name} failed rc={rc}\nstdout: {so.strip()[-300:]}\nstderr: {se.strip()[-200:]}")

        rc, so, se = run_windham(_open(real_loops[0]), binary, timeout=60)
        if rc != 0:
            raise TestFailure(
                f"Open {real_loops[0]} failed rc={rc}\nstdout: {so.strip()[-500:]}\nstderr: {se.strip()[-200:]}")

        # dm-crypt udev events are asynchronous; wait for /dev/mapper symlinks
        subprocess.run(["udevadm", "settle"], capture_output=True)
        time.sleep(0.2)

        mapper_entries = os.listdir("/dev/mapper")
        windham_entries = [e for e in mapper_entries if e.startswith("windham-")]
        opened_count = len(windham_entries)

        # Expected: A(0), B(1), D(3), G(6), E(4) = 5 devices
        expected_names = ["A", "B", "D", "G", "E"]
        pruned_names  = ["C", "F", "H"]
        expected_uuids = set()
        pruned_uuids  = set()

        for lp_idx, name in [(0, "A"), (1, "B"), (3, "D"), (6, "G"), (4, "E")]:
            r = subprocess.run(
                [binary, "Probe", "--dir=" + real_loops[lp_idx], "--no-admin"],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                uid = _parse_uuid_hex(r.stdout)
                if uid:
                    expected_uuids.add(uid)

        for lp_idx, name in [(2, "C"), (5, "F"), (7, "H")]:
            r = subprocess.run(
                [binary, "Probe", "--dir=" + real_loops[lp_idx], "--no-admin"],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                uid = _parse_uuid_hex(r.stdout)
                if uid:
                    pruned_uuids.add(uid)

        mapper_uuids = set()
        for entry in windham_entries:
            if entry.startswith("windham-"):
                mapper_uuids.add(entry[len("windham-"):].replace('-', ''))

        missing = expected_uuids - mapper_uuids
        if missing:
            raise TestFailure(
                f"Expected devices not mapped. Missing: {missing}\nOpened({opened_count}): {mapper_uuids}")

        wrongly_opened = pruned_uuids & mapper_uuids
        if wrongly_opened:
            raise TestFailure(
                f"STOP_EXEC pruned devices should NOT be mapped: {wrongly_opened}\nAll opened: {mapper_uuids}")

        if opened_count != 5:
            raise TestFailure(f"Expected exactly 5 opened devices, got {opened_count}")

        for entry in windham_entries:
            subprocess.run([binary, "Close", entry, "--no-admin"], capture_output=True)

    finally:
        for lp in all_loops:
            subprocess.run([LOSETUP, "-d", lp], capture_output=True)
        for d in all_disks:
            if os.path.exists(d):
                os.remove(d)
