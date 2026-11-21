"""
collector/uuidv7.py
───────────────────
RFC 9562 UUIDv7 implementation.

Format:
  48 bits: Unix timestamp in milliseconds
   4 bits: version (0b0111 = 7)
  12 bits: random sequence
   2 bits: variant (0b10)
  62 bits: random sequence

Matches regex:
  ^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
"""

from __future__ import annotations

import os
import time


def uuidv7() -> str:
    """Generate a time-sortable RFC 9562 UUIDv7 string."""
    # 48-bit timestamp in milliseconds
    ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF

    # 16 bytes of data
    rand_bytes = bytearray(os.urandom(16))

    # Place timestamp in first 6 bytes (48 bits)
    rand_bytes[0] = (ms >> 40) & 0xFF
    rand_bytes[1] = (ms >> 32) & 0xFF
    rand_bytes[2] = (ms >> 24) & 0xFF
    rand_bytes[3] = (ms >> 16) & 0xFF
    rand_bytes[4] = (ms >> 8) & 0xFF
    rand_bytes[5] = ms & 0xFF

    # Byte 6: version 7 (0b0111xxxx)
    rand_bytes[6] = (rand_bytes[6] & 0x0F) | 0x70

    # Byte 8: variant 1 (0b10xxxxxx -> 0x80 to 0xBF)
    rand_bytes[8] = (rand_bytes[8] & 0x3F) | 0x80

    hex_str = rand_bytes.hex()
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"
