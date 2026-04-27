"""RFC-reserved reserved-range fakers (cross-language).

Each function takes (original_value: str, rng: random.Random) -> str and
produces a value in an officially-reserved documentation/test range:
  - email   → RFC 2606 (example.com / .org / .net)
  - IPv4    → RFC 5737 (TEST-NET-1/2/3)
  - IPv6    → RFC 3849 (2001:db8::/32)
  - MAC     → RFC 7042 (00:00:5E:00:53:xx documentation block)
"""

from __future__ import annotations

import random


RFC2606_DOMAINS = ("example.com", "example.org", "example.net")

# RFC 5737 TEST-NET-1/2/3 — guaranteed not routable on the public internet
RFC5737_PREFIXES = ("192.0.2", "198.51.100", "203.0.113")

# RFC 7042 documentation MAC range. The faker varies the last byte only;
# the leading bytes are the IANA-assigned doc block.
RFC7042_MAC_PREFIX = "00:00:5E:00:53"


def fake_email_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate an email under an RFC 2606 reserved domain."""
    local = f"user{rng.randint(1000, 99999)}"
    domain = rng.choice(RFC2606_DOMAINS)
    return f"{local}@{domain}", []


def fake_ip_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a documentation-range IP. Detects v4 vs v6 from the input shape.

    IPv4 → one of RFC 5737 TEST-NET-1/2/3 with random last octet.
    IPv6 → 2001:db8:: with a random 16-bit suffix.
    """
    if ":" in value:
        # IPv6 input → RFC 3849
        suffix = f"{rng.randint(1, 0xFFFF):x}"
        return f"2001:db8::{suffix}", []
    # IPv4 input (default)
    prefix = rng.choice(RFC5737_PREFIXES)
    last = rng.randint(1, 254)
    return f"{prefix}.{last}", []


def fake_mac_reserved(value: str, rng: random.Random) -> tuple[str, list[str]]:
    """Generate a MAC address in the RFC 7042 documentation block."""
    last_byte = rng.randint(0, 255)
    return f"{RFC7042_MAC_PREFIX}:{last_byte:02X}", []
