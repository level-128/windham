#!/bin/bash
# windham-raid-setup — Set up redundant LINK_OPEN cascade for RAID.
#
# Each disk gets two passphrases:
#   1. The user-supplied password (for interactive unlock)
#   2. A randomly-generated key (for cascade LINK_OPEN entries)
#
# The cascade links use the random keys, so reading the aux zone (which
# requires unlocking) does not expose the user's real password.
#
# Usage:
#   sudo ./windham-raid-setup.sh /dev/sda /dev/sdb /dev/sdc
#   sudo ./windham-raid-setup.sh --pass=raidpass /dev/sd{a,b,c}
#
# Options:
#   --pass=<password>    Common password for all disks (default: prompt once)
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
    read -rsp "Common password for all disks: " PASS
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

# Step 1: Create Windham on each disk
echo
echo "--- Step 1: Create Windham partitions ---"
for dev in "${DISKS[@]}"; do
    echo "  Creating on $dev …"
    run sudo windham New "$dev" --key="$PASS" --target-time=0.2 --yes
done

# Step 2: Add a random key to each disk, capture the keys
echo
echo "--- Step 2: Generate random cascade keys ---"
declare -A RANDOM_KEYS
for dev in "${DISKS[@]}"; do
    if $DRY_RUN; then
        RANDOM_KEYS[$dev]="DRY-RUN-HEX-KEY"
        echo "  DRY-RUN: $dev → random key"
        continue
    fi
    echo "  Generating random key for $dev …"
    # AddKey --generate-random-key prints the hex key to stdout (32 bytes = 64 hex chars).
    # We capture it and remove spaces.
    RAW_KEY=$(sudo windham AddKey "$dev" --key="$PASS" \
        --generate-random-key --target-time=0.2 --max-unlock-time=3 --yes)
    # Remove spaces and trailing newline
    KEY=$(echo "$RAW_KEY" | tr -d '[:space:]')
    if [[ -z "$KEY" || ${#KEY} -lt 60 ]]; then
        echo "ERROR: Failed to generate random key for $dev" >&2
        echo "Raw output: $RAW_KEY" >&2
        exit 1
    fi
    RANDOM_KEYS[$dev]="$KEY"
    echo "    Key: ${KEY:0:16}..."
done

# Step 3: Add LINK_OPEN entries based on topology
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
            run sudo windham Aux "$src" --add-link="$dst" \
                --key="$PASS" --target-key="${RANDOM_KEYS[$dst]}" \
                --link-prio=$prio --link-flag=SHORTCUT \
                --max-unlock-time=3 --yes
        done
    else
        # raid5/raid6: link to next HOPS disks clockwise (wraparound)
        for hop in $(seq 1 $HOPS); do
            dst_idx=$(( (i + hop) % N ))
            dst="${DISKS[$dst_idx]}"
            prio=$((prio + 1))
            echo "  $src → $dst (hop=$hop, prio=$prio, SHORTCUT)"
            run sudo windham Aux "$src" --add-link="$dst" \
                --key="$PASS" --target-key="${RANDOM_KEYS[$dst]}" \
                --link-prio=$prio --link-flag=SHORTCUT \
                --max-unlock-time=3 --yes
        done
    fi
done

echo
echo "=== Setup complete ==="
echo
echo "To unlock the cascade:"
echo "  sudo windham Open $OPEN_FIRST --key=\"\$PASS\""
echo
echo "After all disks are mapped, assemble RAID:"
echo "  sudo mdadm --assemble /dev/md0 /dev/mapper/windham-*"
