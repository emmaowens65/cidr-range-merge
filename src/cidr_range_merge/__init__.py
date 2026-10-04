# SPDX-License-Identifier: MIT
"""CIDR range merging for IPv4 and IPv6.

Pure-Python, zero dependencies. Each input CIDR is converted to a
(start, end) inclusive integer pair; pairs are sorted and merged by
sweeping in one pass. Merged runs are re-expressed as the minimal set
of canonical CIDR blocks that exactly cover the run. The same integer
path is used for both families so IPv6 gets identical edge-case
handling for free.
"""

from .core import (
    parse_cidr,
    cidr_to_range,
    range_to_cidrs,
    merge_cidrs,
)

__all__ = [
    "parse_cidr",
    "cidr_to_range",
    "range_to_cidrs",
    "merge_cidrs",
]
