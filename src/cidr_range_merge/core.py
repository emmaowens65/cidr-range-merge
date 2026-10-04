# SPDX-License-Identifier: MIT
"""Core implementation: CIDR -> integer range, merge, range -> CIDRs.

All arithmetic is on plain Python ints. We deliberately do not use the
`ipaddress` module for *parsing*: its `ip_network` constructor rejects
host bits set, but a caller merging firewall rules or route tables often
has imprecise blocks ("10.1.2.5/24") that must be normalized, not
rejected. We still rely on `ipaddress` only to distinguish v4 from v6
and to validate the textual address, which keeps parsing strict where
it matters (no "1.2.3.4.5", no bad hex) without penalizing host bits.
"""

from __future__ import annotations

import ipaddress
from typing import List, Tuple, Union

# A network-family bit width. Using module-level constants instead of
# magic numbers makes the v4/v6 branches visibly symmetric.
_IPV4_BITS = 32
_IPV6_BITS = 128

# Public type aliases. Kept narrow so callers know exactly what to expect:
# endpoints are inclusive integers, not (start, length) or half-open.
Range = Tuple[int, int]
CIDR = Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int]


def parse_cidr(text: str) -> CIDR:
    """Parse a CIDR string into (address, prefix_length).

    Unlike `ipaddress.ip_network`, this tolerates host bits being set
    in the address portion: the caller is asking "what block does this
    address belong to under this prefix?", which is the common case
    when normalizing noisy inputs (e.g. logs, firewall rules). The
    address itself must still be syntactically valid; "10.0.0.999/24"
    raises ValueError.

    The prefix may be omitted, in which case it defaults to the full
    address width (32 for v4, 128 for v6). This mirrors the common
    shorthand of writing a bare address to mean a /32 or /128.
    """
    if not isinstance(text, str):
        raise TypeError(f"expected str, got {type(text).__name__}")

    s = text.strip()
    if not s:
        raise ValueError("empty CIDR string")

    if "/" in s:
        addr_part, _, prefix_part = s.partition("/")
        if not prefix_part or prefix_part != prefix_part.strip():
            # Reject "1.2.3.4/" and "1.2.3.4/ 24" — the slash must be
            # immediately followed by digits. This avoids silently
            # accepting malformed user input.
            raise ValueError(f"invalid prefix in {text!r}")
        try:
            prefix = int(prefix_part)
        except ValueError:
            raise ValueError(f"invalid prefix in {text!r}")
        if prefix < 0:
            raise ValueError(f"negative prefix in {text!r}")
    else:
        addr_part = s
        prefix = -1  # sentinel: full width

    # ipaddress is used purely for validation + family detection. We
    # do not keep the network object because it would have masked host
    # bits, and we want the raw address intact for range math.
    try:
        addr = ipaddress.ip_address(addr_part)
    except ValueError:
        raise ValueError(f"invalid address in {text!r}")

    max_bits = _IPV4_BITS if isinstance(addr, ipaddress.IPv4Address) else _IPV6_BITS
    if prefix == -1:
        prefix = max_bits
    if prefix > max_bits:
        raise ValueError(f"prefix too large for family in {text!r}")

    return addr, prefix


def cidr_to_range(addr, prefix: int) -> Range:
    """Convert (address, prefix) to an inclusive (start, end) integer pair.

    We compute the block size as `1 << (width - prefix)` rather than
    `2 ** (width - prefix)` purely for symmetry with the reverse
    direction; the values are identical on CPython and both are exact
    for the widths involved (max 128).
    """
    if isinstance(addr, ipaddress.IPv4Address):
        width = _IPV4_BITS
    elif isinstance(addr, ipaddress.IPv6Address):
        width = _IPV6_BITS
    else:
        raise TypeError(f"expected IPv4/IPv6 address, got {type(addr).__name__}")
    if not isinstance(prefix, int):
        raise TypeError("prefix must be int")
    if not 0 <= prefix <= width:
        raise ValueError(f"prefix {prefix} out of range for width {width}")

    value = int(addr)
    host_bits = width - prefix
    # Shift rather than mask: shifting gives us the network base and the
    # size in one expression each, and avoids a second branch for the
    # full-width case (host_bits == 0 => shift by 0 => value itself).
    base = value >> host_bits << host_bits
    size = 1 << host_bits
    return base, base + size - 1


def range_to_cidrs(start: int, end: int, ipv6: bool) -> List[CIDR]:
    """Express an inclusive integer range as the minimal CIDR cover.

    Algorithm: at each step, emit the largest CIDR aligned to the
    current start that does not overshoot `end`. "Largest aligned" is
    governed by two constraints — the number of trailing zero bits in
    `start` (alignment) and the remaining size to `end` (capacity). The
    CIDR width is `min(zeros, log2(remaining))`. This is the standard
    greedy and it is provably minimal for a single contiguous range.

    `ipv6` selects the address width and the address class returned.
    Passing the family explicitly (rather than sniffing from the size
    of the integers) keeps the function total on inputs like (0, 255),
    which are ambiguous.
    """
    if not isinstance(start, int) or not isinstance(end, int):
        raise TypeError("start and end must be int")
    if start < 0 or end < 0:
        raise ValueError("start and end must be non-negative")
    if start > end:
        raise ValueError("start must be <= end")

    width = _IPV6_BITS if ipv6 else _IPV4_BITS
    max_value = (1 << width) - 1
    if end > max_value:
        raise ValueError(f"end {end} exceeds family width {width}")

    addr_cls = ipaddress.IPv6Address if ipv6 else ipaddress.IPv4Address
    out: List[CIDR] = []
    cur = start
    # Invariant: [start, cur) is covered; we extend toward `end`.
    while cur <= end:
        # Alignment: trailing zeros of cur cap the block size. We use
        # bit_length on the *complement* so that cur == 0 reports the
        # full width rather than crashing on log2(0).
        if cur == 0:
            max_by_align = width
        else:
            max_by_align = (cur & -cur).bit_length() - 1
        # Capacity: how many addresses fit without overshooting end.
        remaining = end - cur + 1
        max_by_cap = remaining.bit_length() - 1
        block_bits = max_by_align if max_by_align < max_by_cap else max_by_cap
        # block_bits is the log2 of the block size; prefix is its complement.
        prefix = width - block_bits
        size = 1 << block_bits
        out.append((addr_cls(cur), prefix))
        cur += size
    return out


def merge_cidrs(cidrs: List[str]) -> List[str]:
    """Merge a list of CIDR strings into the minimal covering set.

    Returns canonical "base/prefix" strings, sorted ascending. v4 and
    v6 are merged *together* but kept in separate families internally:
    a v4 block can never combine with a v6 block, so mixing them in the
    input yields a result that is the union of two independent merges.
    This is the only sensible interpretation — cross-family merge is not
    meaningful — and it is documented in the README.

    Deduplication of identical inputs is handled by the same sweep that
    merges overlaps, so callers do not need to pre-dedupe.
    """
    if not isinstance(cidrs, (list, tuple)):
        raise TypeError(f"expected list/tuple, got {type(cidrs).__name__}")

    v4_ranges: List[Range] = []
    v6_ranges: List[Range] = []
    for raw in cidrs:
        addr, prefix = parse_cidr(raw)
        start, end = cidr_to_range(addr, prefix)
        if isinstance(addr, ipaddress.IPv4Address):
            v4_ranges.append((start, end))
        else:
            v6_ranges.append((start, end))

    results: List[str] = []
    for ranges, ipv6 in ((v4_ranges, False), (v6_ranges, True)):
        if not ranges:
            continue
        # Sort by start, then end. Sorting by end too is what makes the
        # subsequent merge a single forward sweep with no need to look
        # back: any later range that starts before the current end must
        # also end no earlier (else it is fully contained).
        ranges.sort(key=lambda r: (r[0], r[1]))
        merged: List[Range] = []
        cur_s, cur_e = ranges[0]
        for s, e in ranges[1:]:
            # `<=` rather than `<` because adjacency (cur_e + 1 == s)
            # also merges: 10.0.0.0/31 and 10.0.0.2/31 become 10.0.0.0/30.
            if s <= cur_e + 1:
                if e > cur_e:
                    cur_e = e
            else:
                merged.append((cur_s, cur_e))
                cur_s, cur_e = s, e
        merged.append((cur_s, cur_e))

        for s, e in merged:
            for addr, prefix in range_to_cidrs(s, e, ipv6):
                results.append(f"{addr}/{prefix}")

    # Within a family range_to_cidrs already produces ascending order;
    # we sort across families purely to give callers a stable, obvious
    # ordering (v4 sorts before v6 lexicographically because digits <
    # letters in ASCII, which happens to match intuition).
    results.sort(key=lambda r: (int(ipaddress.ip_address(r.split("/")[0])), r))
    return results
