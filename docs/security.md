# Security Model

## Key hierarchy

Every Windham partition has one **master key** — a 256-bit random secret generated
when the device is created. From this single key, Windham derives separate keys for
each purpose: one to protect the header metadata, one to encrypt your disk data,
and one to lock the auxiliary data zone.

Your passphrase unlocks the master key through a memory-hard key derivation function
(Argon2id). The derivation repeats across increasingly memory-intensive levels until
it either succeeds or reaches your configured time or memory limits. Each passphrase
slot gets its own set of derivation parameters, so two passphrases on the same device
are independent — one cannot be used to speed up cracking the other.

The master key itself never changes. It is the root of all security: lose it, and
your data is gone. Back it up with `windham Open --dry-run` and store it securely.

---

## Never clone a header

**DO NOT copy a Windham header from one device to another.** Every header is unique —
it contains a randomly generated master key and a device-specific identifier. If two
devices share the same header, they share the same master key: breaking into one gives
you access to both. This is why you should always create each device with `windham New`,
even if you plan to use the same passphrase.

---

## Glossary

**KDF (Key Derivation Function)** — A one-way function that turns a passphrase into
a cryptographic key. Windham uses Argon2id, a memory-hard KDF that forces attackers
to spend RAM (not just CPU cycles) on each guess, making brute-force attacks
exponentially more expensive.

**Key slot / passphrase slot** — One of 16 independent passphrase registrations.
Each slot spans two regions: the metadata area holds the slot's identifier and
bookkeeping (which level, where in the keypool), while the keypool area holds the
raw derivation data (key masks and salts) across two zones.

**Keypool** — The larger (~18 KB) random data region inside the header where actual
slot derivation data (key masks, salts, and iteration sizes) is stored across two
redundant zones (zone 0 and zone 1). Each key slot's position inside the keypool is
deterministic: it is calculated from a hash of the passphrase and `master_key_mask`.

**Rapid-add vs header re-transform** — When you add a key, Windham can either update
the header incrementally (rapid-add) or recalculate everything from scratch
(re-transform). Rapid-add is fast — it writes only the new slot into an empty
keypool area — but leaves the existing structure intact, making it vulnerable to
the slot history attack. Re-transform regenerates most of the header's random
components, shuffles all slot positions, and re-encrypts the aux zone — slow but
cryptographically opaque to snapshot comparison. Use rapid-add for cold storage
or when no adversary can observe the device between transactions; use re-transform
(the default) otherwise.

Rapid-add is probabilistic: The slot location is fixed by that hash. In rapid mode,
`master_key_mask` is never changed, so new slots must fit into the existing layout
without overlapping any previously placed slots. Each slot is assigned to one of
the two zones (without redundancy in this context), and Windham
checks for overlaps only within the target zone. The second key added always succeeds
because the first key occupies only one zone — the other zone is empty and guarantees
a collision-free placement. Once both zones have at least one slot, each subsequent
rapid-add risks overlapping with both zones simultaneously. If the calculated location
overlaps with every occupied slot in both zones, rapid-add fails and you must use
normal (non-rapid) AddKey. With many registered keys — especially at high KDF levels
where slot sizes are larger — the probability of both-zone collision increases,
eventually requiring a full re-transform.

**Anonymous key** — A key slot with its identifier (the SHA-256 hash of the raw
password) zeroed out. This hides which slots are occupied and blocks the key
identifier attack, at the cost of not surviving non-rapid re-transforms.

**Decoy Partition** — An encrypted Windham partition hidden under a visible,
identifiable partition (usually the last GPT partition). Readable as a normal
filesystem, but secretly holding encrypted data at its end. See
[docs/decoy.md](decoy.md).

**Aux zone (auxiliary data zone)** — An optional metadata area after the header,
storing per-key encrypted entries: plaintext notes, shell commands executed on
open, and LINK_OPEN references to other encrypted devices. See [docs/auxzone.md](auxzone.md).

**LINK_OPEN cascade** — When you open one device with `--aux-link`, any LINK_OPEN aux entries it
contains cause linked devices to be automatically unlocked in a priority-ordered
chain. One unlocked partition can trigger an entire tree of devices.

**Plausible deniability** — The property that no observer can prove a given block
device is a Windham partition. Every byte of the header is either random or
encrypted, with no persistent signature or magic number (unless you explicitly
add the optional tags).

**Windhamtab** — `/etc/windhamtab`, a configuration file similar to systemd's
`/etc/crypttab`, that lists encrypted devices to unlock at boot. See
[docs/windhamtab.md](windhamtab.md).

---

## Slot history attack

**Threat**: An adversary with read access to the device both before and after an
`AddKey` operation can compare the header snapshots. If `--rapid-add` was used,
the adversary can identify roughly which keypool regions has changed, dramatically
reducing the brute-force search space (30–100× advantage).

**Mitigation — 1. Use normal AddKey (default)**: Every non-rapid `AddKey` performs a full
**header re-transform**:

1. Regenerates `master_key_mask` with fresh random data
2. Recalculates all keypool locations (they depend on `sha256(master_key_mask, inited_key)`)
3. Re-derives all existing key masks with the new `master_key_mask`
4. Re-encrypts the aux zone with the new CBC IV
5. Fills all unused keypool regions with random data (side-channel padding)

After re-transform, most bytes in the header changed — the adversary cannot
correlate snapshots to deduce which passphrase was added.

**Mitigation — 2. Random broadcast when Rapid**: 
In rapid mode, only the single new key slot is
generated and placed into an empty keypool location. `master_key_mask` is NOT
changed, existing slots are NOT recalculated, and the aux zone is NOT re-encrypted.
Only some bytes at the target keypool location are written, covered by extra random
fragments. The adversary can identify the potential changed region, gaining a significant
brute-force advantage. Only use `--rapid-add` if you are certain no adversary can
access the device between transactions (e.g., cold storage, offline backups).

### Performance of header re-transform

Re-transform time scales with the number of registered passphrases. Each existing
slot must be re-derived. For a device with 15 existing passphrases, a non-rapid
`AddKey` can take minutes. This is the trade-off: security vs speed.

`--rapid-add` is always safe if the slot history attack does not apply to your
threat model.

---

## Anonymous keys

**Threat — key identifier attack**: An attacker who can unlock one passphrase gains
access to decrypted metadata, including internal `keyslot_key[i]` for all other slots.
`keyslot_key[i]` is `SHA-256(password_bytes)` — the first KDF input. Knowing this
gives the attacker a ~4–5 order-of-magnitude computational advantage when brute-forcing
other non-anonymous passphrases (the attacker can skip the initial KDF stage).

**Mitigation**: Enroll a key with `--anonymous-key`. This zeroes the `keyslot_key`
field in metadata. The slot still functions normally for unlock, but:

- No identifier is stored — the slot cannot be targeted by identifier-based attacks
- Anonymous keys cannot survive a non-rapid header re-transform (AddKey without `--rapid-add`
  removes them, since re-transform requires `keyslot_key` to recompute locations)
- They provide significantly more resistance against adversaries who can read metadata

**Which keys should be anonymous?** Passphrases and low-entropy keys benefit most.
High-entropy keys (random key files, Clevis-encrypted keys) are already resistant
to brute-force and don't need anonymity.

**`DelKey --anonymous-key`**: Converts an existing non-anonymous key to anonymous
by zeroing `keyslot_key` and `keyslot_location` without removing the keypool data.

---


## Tamper resistance

### Suspended state

When a device is suspended (via `Suspend`), the intermediate disk encryption key is
stored in the header so the device can be opened without a password (`Open` works,
but only `Open` and `Close`). `Resume` restores normal password-required operation.

**What suspend exposes:** The partition geometry (encryption type, sector range,
block size, aux zone location) becomes readable. A recognizable "suspend" tag marks
the header. The disk encryption key is stored in an intermediate, reversed form
that can only be restored by someone who knows the original passphrase or master key.

**What suspend does NOT expose:** Your passphrases remain encrypted. None of the
16 key slots are decrypted. The auxiliary data zone stays fully encrypted — no one
can read your aux entries or follow your LINK_OPEN chains. The master key itself
cannot be derived from the suspended state, nor can any passphrase be recovered
from it.

**Why a suspended header should never be modified:** Suspending embeds the disk
encryption key into the header in a reversible form. The reversal is only possible
with the original passphrase or master key. Any change to the header — even
well-intentioned ones like extending the encrypted area — breaks this relationship.
If you then try to resume, the device may be permanently unopenable, even with the
correct password. If you need to modify a suspended device, resume it first.

### Integrity checks

Windham uses multiple layers of built-in validation to detect tampering, corruption,
or incorrect passphrases before any data is touched:

- After deriving a key from your passphrase, Windham verifies it against a
  checksum hidden in the header. If the key doesn't match, the attempt is rejected
  immediately — no wasted time trying to decrypt data with a wrong key.
- The header metadata is encrypted with a key derived from the master key. A
  known marker inside the metadata must survive decryption intact. If the header
  has been damaged or tampered with, this marker won't match and Windham will
  refuse to proceed.
- The device's unique identifier doubles as a salt for key derivation. Changing
  any part of the header — even in ways that look harmless — changes the salt,
  which changes every derived key. The result is a device that simply won't open.

---

## Plausible deniability

Windham's on-disk format uses no persistent magic numbers, signatures, or file-system
identifiers. Every byte of the header (except optional user-facing tags) is
cryptographically random or encrypted.

Two **optional** tags exist for external tooling (ignored by Windham itself):

- `windham_partition_magic` (16 bytes at header offset 16): ASCII `"windhamlevel-128"`.
  Intended for partitioning tools to identify Windham devices.
- `shebang_line` (16 bytes at header offset 0): ASCII `"#!/bin/windham\n"`. Enables
  the binary to act as a self-decrypting executable.

Both can be removed with `dd if=/dev/urandom` if maximum deniability is required.

The **Decoy Partition** feature provides an additional layer — hiding the encrypted
data under a visible plaintext filesystem. See [docs/decoy.md](decoy.md).

---

## Memory and key hygiene

- Set `--max-unlock-memory` to limit KDF memory usage on constrained systems.
- Use `--nokeyring` to prevent disk keys from being stored in the kernel keyring.
- `--timeout` controls how long a keyring-stored key remains valid.
- The `--allow-swap` flag permits KDF memory to be paged to swap. **DO NOT enable
  this if your swap device stores data in plaintext.** It is disabled by default
  at compile time (`CFG_USE_SWAP`).

---

## Side-channel resistance

### KDF memory wiggle

Starting at KDF level 3 (~22 MiB memory), the exact memory allocation per iteration
is randomized by a hash of the previous output XORed with `master_key_mask`. The wiggle
scale ranges from 0.013% (level 3) to 0.02% (level 25, ~220 TiB). This prevents
attackers from building fixed-size custom hardware for KDF acceleration.

### Upper-bound allocation

Windham always allocates the **upper bound** of the wiggle range for each iteration.
This prevents page-fault-based side channels that could measure the exact memory
footprint.

### Speculation mitigation

The Release build enables `PR_SET_SPECULATION_CTRL` (Spectre v2 mitigation) by default.
This prevents speculative execution attacks on in-memory key material.

### Debugger prevention

Release builds block debugger attachment (`prctl(PR_SET_DUMPABLE)`). This prevents
an attacker with local access from attaching a debugger to read keys from memory.
Debug builds (`-DCMAKE_BUILD_TYPE=Debug`) allow attachment for development.

### Memory wiping

After KDF completes, the internal Argon2 working memory can optionally be zeroed
to prevent residual key material from lingering in freed heap pages. This is
controlled by the compile-time flag `CFG_WIPE_MEMORY` and is **disabled by default**
because it adds measurable overhead to every unlock. Enable it only if your threat
model includes an attacker who can inspect freed memory pages before the OS reclaims
or overwrites them — a niche concern on most systems but relevant for security
audits and hardened deployments.

---