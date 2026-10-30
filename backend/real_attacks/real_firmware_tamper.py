"""
real_attacks/real_firmware_tamper.py
=======================================
SAFETY NOTE
-----------
This only ever reads/writes files inside this package's own
`firmware_store/` folder, created next to this script. It never
touches any file elsewhere on disk.

WHAT THIS ACTUALLY DOES
------------------------
1. Maintains a real "golden" firmware file (firmware_store/golden.bin)
   and computes its real SHA-256 hash with Python's stdlib `hashlib`
   - the exact same algorithm real embedded devices use for firmware
   signature verification.
2. Maintains a real "device" copy (firmware_store/device.bin) that
   represents what's actually running on the simulated relay.
3. On start(): genuinely flips real bytes at random offsets inside the
   device copy (an actual file mutation on disk), then recomputes its
   real SHA-256 hash and compares it - byte for byte - against the
   golden hash. The mismatch this reports is a real hashlib.sha256()
   comparison result, not a random boolean.
4. On resolve() (called when the dashboard's mitigation phase
   completes): genuinely copies the golden file back over the device
   file - a real file-level rollback to the last known-good firmware,
   which is literally what "rolling back to a signed firmware image"
   means for a real embedded device.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/real_firmware_tamper.py
"""

import hashlib
import os
import random
import shutil

STORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware_store")
GOLDEN_PATH = os.path.join(STORE_DIR, "golden.bin")
DEVICE_PATH = os.path.join(STORE_DIR, "device.bin")

FIRMWARE_SIZE_BYTES = 4096
BYTES_TO_CORRUPT = 6  # how many bytes get flipped during a tamper event


def _sha256_of(path):
    """Real SHA-256 digest of a real file's real contents on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _ensure_golden_exists():
    os.makedirs(STORE_DIR, exist_ok=True)
    if not os.path.exists(GOLDEN_PATH):
        # Deterministic "firmware" content so re-runs are reproducible.
        rng = random.Random(1234)
        content = bytes(rng.getrandbits(8) for _ in range(FIRMWARE_SIZE_BYTES))
        with open(GOLDEN_PATH, "wb") as f:
            f.write(content)
    if not os.path.exists(DEVICE_PATH):
        shutil.copyfile(GOLDEN_PATH, DEVICE_PATH)


class RealFirmwareTamperRunner:
    """Not a continuous process like the other two - firmware tampering
    is a discrete event, so start() performs one real corruption and
    the state is read repeatedly via get_live_metrics() until
    resolve() performs the real rollback."""

    def __init__(self):
        _ensure_golden_exists()
        self._golden_hash = _sha256_of(GOLDEN_PATH)
        self._device_hash = self._golden_hash
        self._tampered = False
        self._corrupted_offsets = []

    def start(self):
        """Genuinely corrupts real bytes in the real device file."""
        with open(DEVICE_PATH, "r+b") as f:
            size = os.path.getsize(DEVICE_PATH)
            offsets = random.sample(range(size), BYTES_TO_CORRUPT)
            self._corrupted_offsets = sorted(offsets)
            for off in offsets:
                f.seek(off)
                original_byte = f.read(1)
                new_byte = bytes([(original_byte[0] + 1) % 256])  # flip it to something different
                f.seek(off)
                f.write(new_byte)

        self._device_hash = _sha256_of(DEVICE_PATH)  # REAL recomputed hash after REAL corruption
        self._tampered = self._device_hash != self._golden_hash
        self._running = True

    def resolve(self):
        """Genuine rollback: real file copy of the golden image back
        over the (really) corrupted device file."""
        shutil.copyfile(GOLDEN_PATH, DEVICE_PATH)
        self._device_hash = _sha256_of(DEVICE_PATH)
        self._tampered = self._device_hash != self._golden_hash  # will be False again, for real
        self._running = False

    @property
    def is_running(self):
        return getattr(self, "_running", False)

    def get_live_metrics(self):
        return {
            # real 0.0/1.0 from an actual hash comparison, not a formula
            "firmware_checksum_mismatch": 1.0 if self._tampered else 0.0,
            "golden_sha256": self._golden_hash,
            "device_sha256": self._device_hash,
            "corrupted_byte_offsets": self._corrupted_offsets,
            "tampered": self._tampered,
        }


if __name__ == "__main__":
    runner = RealFirmwareTamperRunner()
    print("Golden firmware SHA-256:", runner._golden_hash)
    print("Device firmware SHA-256 (before tamper):", runner._device_hash)
    print("Match:", runner._golden_hash == runner._device_hash)

    print("\nCorrupting real bytes in the device firmware file...")
    runner.start()
    m = runner.get_live_metrics()
    print("Device firmware SHA-256 (after tamper):", m["device_sha256"])
    print("Corrupted byte offsets:", m["corrupted_byte_offsets"])
    print("Checksum mismatch detected:", bool(m["firmware_checksum_mismatch"]))

    print("\nRolling back to golden image...")
    runner.resolve()
    m = runner.get_live_metrics()
    print("Device firmware SHA-256 (after rollback):", m["device_sha256"])
    print("Checksum mismatch after rollback:", bool(m["firmware_checksum_mismatch"]))
