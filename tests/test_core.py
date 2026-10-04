# SPDX-License-Identifier: MIT
"""Tests for cidr_range_merge.core.

Covers parsing, range conversion, CIDR re-emission, and the end-to-end
merge. Edge cases are chosen for the code paths that actually exist:
host-bit normalization, adjacency merge, containment, cross-family
independence, and the zero-start alignment branch in range_to_cidrs.
"""

import unittest
import ipaddress

from cidr_range_merge.core import (
    parse_cidr,
    cidr_to_range,
    range_to_cidrs,
    merge_cidrs,
)


class TestParseCIDR(unittest.TestCase):
    def test_v4_with_host_bits(self):
        addr, prefix = parse_cidr("10.1.2.5/24")
        self.assertEqual(addr, ipaddress.IPv4Address("10.1.2.5"))
        self.assertEqual(prefix, 24)

    def test_v6_with_host_bits(self):
        addr, prefix = parse_cidr("2001:db8::1/64")
        self.assertEqual(addr, ipaddress.IPv6Address("2001:db8::1"))
        self.assertEqual(prefix, 64)

    def test_bare_address_defaults_full_prefix(self):
        addr, prefix = parse_cidr("192.0.2.7")
        self.assertEqual(prefix, 32)
        addr6, prefix6 = parse_cidr("2001:db8::abcd")
        self.assertEqual(prefix6, 128)

    def test_rejects_bad_address(self):
        with self.assertRaises(ValueError):
            parse_cidr("10.0.0.999/24")

    def test_rejects_prefix_too_large(self):
        with self.assertRaises(ValueError):
            parse_cidr("10.0.0.0/33")
        with self.assertRaises(ValueError):
            parse_cidr("::1/129")

    def test_rejects_empty_and_whitespace_prefix(self):
        with self.assertRaises(ValueError):
            parse_cidr("")
        with self.assertRaises(ValueError):
            parse_cidr("10.0.0.0/ 24")
        with self.assertRaises(ValueError):
            parse_cidr("10.0.0.0/")

    def test_rejects_non_string(self):
        with self.assertRaises(TypeError):
            parse_cidr(123)  # type: ignore[arg-type]


class TestCidrToRange(unittest.TestCase):
    def test_v4_full_block(self):
        self.assertEqual(
            cidr_to_range(ipaddress.IPv4Address("10.0.0.0"), 24),
            (0x0A000000, 0x0A0000FF),
        )

    def test_v4_host_bits_ignored_for_base(self):
        # 10.1.2.5/24 — host bits set in input but range is the whole /24.
        self.assertEqual(
            cidr_to_range(ipaddress.IPv4Address("10.1.2.5"), 24),
            (0x0A010200, 0x0A0102FF),
        )

    def test_v4_single_host(self):
        self.assertEqual(
            cidr_to_range(ipaddress.IPv4Address("8.8.8.8"), 32),
            (0x08080808, 0x08080808),
        )

    def test_v4_default_route(self):
        self.assertEqual(
            cidr_to_range(ipaddress.IPv4Address("0.0.0.0"), 0),
            (0, 0xFFFFFFFF),
        )

    def test_v6_single_host(self):
        a = ipaddress.IPv6Address("2001:db8::1")
        self.assertEqual(cidr_to_range(a, 128), (int(a), int(a)))

    def test_v6_default_route(self):
        start, end = cidr_to_range(ipaddress.IPv6Address("::"), 0)
        self.assertEqual(start, 0)
        self.assertEqual(end, (1 << 128) - 1)

    def test_rejects_bad_prefix(self):
        with self.assertRaises(ValueError):
            cidr_to_range(ipaddress.IPv4Address("10.0.0.0"), -1)
        with self.assertRaises(ValueError):
            cidr_to_range(ipaddress.IPv4Address("10.0.0.0"), 33)

    def test_rejects_bad_address_type(self):
        with self.assertRaises(TypeError):
            cidr_to_range("10.0.0.0", 24)  # type: ignore[arg-type]


class TestRangeToCIDRs(unittest.TestCase):
    def test_already_canonical_single_block(self):
        # 10.0.0.0 - 10.0.0.255 is exactly a /24
        cidrs = range_to_cidrs(0x0A000000, 0x0A0000FF, ipv6=False)
        self.assertEqual(cidrs, [(ipaddress.IPv4Address("10.0.0.0"), 24)])

    def test_split_around_alignment_boundary(self):
        # 10.0.0.1 - 10.0.0.6 cannot be one block; alignment forces a split.
        # The minimal cover is /32 + /31 + /31 + /32: addresses 1, 2-3, 4-5, 6.
        cidrs = range_to_cidrs(0x0A000001, 0x0A000006, ipv6=False)
        self.assertEqual(
            cidrs,
            [
                (ipaddress.IPv4Address("10.0.0.1"), 32),
                (ipaddress.IPv4Address("10.0.0.2"), 31),
                (ipaddress.IPv4Address("10.0.0.4"), 31),
                (ipaddress.IPv4Address("10.0.0.6"), 32),
            ],
        )

    def test_single_address_range(self):
        cidrs = range_to_cidrs(0x0A000005, 0x0A000005, ipv6=False)
        self.assertEqual(cidrs, [(ipaddress.IPv4Address("10.0.0.5"), 32)])

    def test_full_v4_space_from_zero(self):
        cidrs = range_to_cidrs(0, 0xFFFFFFFF, ipv6=False)
        self.assertEqual(cidrs, [(ipaddress.IPv4Address("0.0.0.0"), 0)])

    def test_zero_start_alignment_branch(self):
        # Exercises the `cur == 0` branch specifically.
        cidrs = range_to_cidrs(0, 0xFFFF, ipv6=False)
        self.assertEqual(cidrs, [(ipaddress.IPv4Address("0.0.0.0"), 16)])

    def test_v6_range(self):
        start = int(ipaddress.IPv6Address("2001:db8::"))
        end = start + (1 << 64) - 1
        cidrs = range_to_cidrs(start, end, ipv6=True)
        self.assertEqual(cidrs, [(ipaddress.IPv6Address("2001:db8::"), 64)])

    def test_rejects_inverted_range(self):
        with self.assertRaises(ValueError):
            range_to_cidrs(10, 5, ipv6=False)

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            range_to_cidrs(-1, 5, ipv6=False)

    def test_rejects_end_exceeds_family_width(self):
        with self.assertRaises(ValueError):
            range_to_cidrs(0, 1 << 32, ipv6=False)


class TestMergeCIDRs(unittest.TestCase):
    def test_adjacent_merge(self):
        self.assertEqual(
            merge_cidrs(["10.0.0.0/31", "10.0.0.2/31"]),
            ["10.0.0.0/30"],
        )

    def test_overlapping_merge(self):
        self.assertEqual(
            merge_cidrs(["10.0.0.0/24", "10.0.0.128/25"]),
            ["10.0.0.0/24"],
        )

    def test_contained_input_deduplicated(self):
        self.assertEqual(
            merge_cidrs(["10.0.0.0/24", "10.0.0.0/25", "10.0.0.5/32"]),
            ["10.0.0.0/24"],
        )

    def test_disjoint_stay_separate(self):
        self.assertEqual(
            merge_cidrs(["10.0.0.0/24", "10.0.2.0/24"]),
            ["10.0.0.0/24", "10.0.2.0/24"],
        )

    def test_host_bits_normalized(self):
        self.assertEqual(
            merge_cidrs(["10.0.0.5/24", "10.0.0.200/25"]),
            ["10.0.0.0/24"],
        )

    def test_v4_and_v6_independent(self):
        # A v4 block and a v6 block with overlapping integer values must
        # NOT combine — they belong to different address families.
        result = merge_cidrs(["0.0.0.0/0", "::/0"])
        self.assertEqual(result, ["0.0.0.0/0", "::/0"])

    def test_v6_adjacent_merge(self):
        self.assertEqual(
            merge_cidrs(["2001:db8::/65", "2001:db8:0:0:8000::/65"]),
            ["2001:db8::/64"],
        )

    def test_empty_input(self):
        self.assertEqual(merge_cidrs([]), [])

    def test_result_is_sorted(self):
        result = merge_cidrs(["10.0.2.0/24", "10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual(
            result,
            ["10.0.0.0/23", "10.0.2.0/24"],
        )

    def test_rejects_non_list(self):
        with self.assertRaises(TypeError):
            merge_cidrs("10.0.0.0/24")  # type: ignore[arg-type]

    def test_bare_address_inputs(self):
        # Two adjacent single hosts merge to a /31.
        self.assertEqual(
            merge_cidrs(["192.0.2.0", "192.0.2.1"]),
            ["192.0.2.0/31"],
        )

    def test_unsorted_overlapping_inputs(self):
        self.assertEqual(
            merge_cidrs(["10.0.0.8/29", "10.0.0.0/29", "10.0.0.4/30"]),
            ["10.0.0.0/28"],
        )


if __name__ == "__main__":
    unittest.main()
