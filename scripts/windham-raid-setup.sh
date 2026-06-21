#!/bin/bash
# windham-raid-setup — Set up redundant LINK_OPEN cascade for RAID.
#
# All disks share a single random high-entropy key (for cascade LINK_OPEN).
# The user's password is added as a second slot via rapid-add on each disk
# after creation.
#
# Usage:
#   sudo ./windham-raid-setup.sh /dev/sda /dev/sdb /dev/sdc
#   sudo ./windham-raid-setup.sh --pass=userpass /dev/sd{a,b,c}
#
# Options:
#   --pass=<password>    User password (default: prompt once)
#   --open-first=<disk>  Which disk to open to trigger cascade (default: first arg)
#   --raid=all|raid5|raid6  Link topology (default: all)
#                          all   — every disk links to every other disk
#                          raid5 — each disk links to next 2 (tolerates 1 failure)
#                          raid6 — each disk links to next 3 (tolerates 2 failures)
#   --dry-run            Print commands without executing

set -e

DRY_RUN=false
PASS=""
OPEN_FIRST=""
RAID_MODE="all"

usage() {
    echo "Usage: $0 [--pass=<pw>] [--raid=all|raid5|raid6] [--open-first=<disk>] [--dry-run] /dev/sda /dev/sdb ..."
    exit 1
}

# Parse args
DISKS=()
for arg in "$@"; do
    case "$arg" in
        --pass=*)       PASS="${arg#*=}" ;;
        --open-first=*) OPEN_FIRST="${arg#*=}" ;;
        --dry-run)      DRY_RUN=true ;;
        --raid=*)       RAID_MODE="${arg#*=}" ;;
        --help|-h)      usage ;;
        /dev/*)         DISKS+=("$arg") ;;
        *)              echo "Unknown argument: $arg"; usage ;;
    esac
done

N=${#DISKS[@]}
if [[ "$RAID_MODE" == "raid5" ]]; then
    (( N >= 3 )) || { echo "raid5 needs at least 3 disks." >&2; exit 1; }
    MAX_FAIL=1
    HOPS=2
elif [[ "$RAID_MODE" == "raid6" ]]; then
    (( N >= 4 )) || { echo "raid6 needs at least 4 disks." >&2; exit 1; }
    MAX_FAIL=2
    HOPS=3
elif [[ "$RAID_MODE" == "all" ]]; then
    (( N >= 3 )) || { echo "Need at least 3 disks." >&2; exit 1; }
    MAX_FAIL=$(( (N-1)/2 ))
    HOPS=0  # 0 means "all others"
else
    echo "Unknown --raid mode: $RAID_MODE (valid: all, raid5, raid6)" >&2
    exit 1
fi

OPEN_FIRST="${OPEN_FIRST:-${DISKS[0]}}"

# Prompt for password if not given
if [[ -z "$PASS" ]]; then
    read -rsp "Your password for interactive unlock: " PASS
    echo
    if [[ -z "$PASS" ]]; then
        echo "Empty password." >&2
        exit 1
    fi
fi

run() {
    if $DRY_RUN; then
        echo "  DRY-RUN: $*"
    else
        "$@"
    fi
}

echo "=== RAID cascade setup: $N disks (mode=$RAID_MODE) ==="
echo "  Disks: ${DISKS[*]}"
echo "  Open-first: $OPEN_FIRST"
echo "  Fault tolerance: $MAX_FAIL disk(s)"

# Step 0: Generate one shared random key
echo
echo "--- Step 0: Generate shared cascade key ---"
if $DRY_RUN; then
    CASCADE_KEY="DRY-RUN-64-HEX-KEY"
else
    CASCADE_KEY=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -A n -t x1 | tr -d ' \n')
    if [[ -z "$CASCADE_KEY" || ${#CASCADE_KEY} -lt 60 ]]; then
        echo "ERROR: Failed to generate cascade key." >&2
        exit 1
    fi
fi
echo "  Cascade key: ${CASCADE_KEY:0:16}..."

# Step 1: Create Windham on each disk using the shared cascade key
echo
echo "--- Step 1: Create Windham partitions with cascade key ---"
for dev in "${DISKS[@]}"; do
    echo "  Creating on $dev …"
    run sudo windham New "$dev" --key="$CASCADE_KEY" --target-time=0.2 --yes
done

# Step 2: Add user password to each disk via rapid-add (non-interactive)
echo
echo "--- Step 2: Add user password to each disk (rapid-add) ---"
for dev in "${DISKS[@]}"; do
    echo "  Adding user key to $dev …"
    run sudo windham AddKey "$dev" --key="$CASCADE_KEY" --new-key="$PASS" \
        --rapid-add --target-time=0.2 --max-unlock-time=3 --yes
done

# Step 3: Add LINK_OPEN entries (all disks share the cascade key)
echo
echo "--- Step 3: Add LINK_OPEN entries (mode=$RAID_MODE) ---"
prio=0
for i in "${!DISKS[@]}"; do
    src="${DISKS[$i]}"
    if [[ $HOPS -eq 0 ]]; then
        # all: link to every other disk
        for j in "${!DISKS[@]}"; do
            [[ $i -eq $j ]] && continue
            dst="${DISKS[$j]}"
            prio=$((prio + 1))
            echo "  $src → $dst (prio=$prio, SHORTCUT)"
            run sudo windham Aux "$src" --aux-add-link="$dst" \
                --key="$CASCADE_KEY" --aux-target-key="$CASCADE_KEY" \
                --aux-link-prio=$prio --aux-link-flag=SHORTCUT \
                --max-unlock-time=3 --yes
        done
    else
        for hop in $(seq 1 $HOPS); do
            dst_idx=$(( (i + hop) % N ))
            dst="${DISKS[$dst_idx]}"
            prio=$((prio + 1))
            echo "  $src → $dst (hop=$hop, prio=$prio, SHORTCUT)"
            run sudo windham Aux "$src" --aux-add-link="$dst" \
                --key="$CASCADE_KEY" --aux-target-key="$CASCADE_KEY" \
                --aux-link-prio=$prio --aux-link-flag=SHORTCUT \
                --max-unlock-time=3 --yes
        done
    fi
done

echo
echo "=== Setup complete ==="
echo
echo "To unlock the cascade with the cascade key:"
echo "  sudo windham Open $OPEN_FIRST --key=\"$CASCADE_KEY\""
echo
echo "To unlock with your password:"
echo "  sudo windham Open $OPEN_FIRST"
echo
echo "After all disks are mapped, assemble RAID:"
echo "  sudo mdadm --assemble /dev/md0 /dev/mapper/windham-*"
