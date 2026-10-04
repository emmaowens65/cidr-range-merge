# cidr-range-merge

Merge adjacent and overlapping IPv4/IPv6 CIDR blocks into the minimal covering set, using pure-Python integer arithmetic with no third-party dependencies.

## Usage

```python
from cidr_range_merge import merge_cidrs

merge_cidrs(["10.0.0.0/24", "10.0.0.128/25", "2001:db8::/65", "2001:db8:0:0:8000::/65"])
# -> ['10.0.0.0/24', '2001:db8::/64']
```

The exported names are: `parse_cidr`, `cidr_to_range`, `range_to_cidrs`, and `merge_cidrs`. `merge_cidrs` takes a list of CIDR strings and returns a sorted list of canonical `base/prefix` strings.

## Why this exists

Firewall rules, route tables, and log-derived allow-lists accumulate redundant or overlapping CIDR entries over time. Carrying them verbatim bloats configs and makes diffs noisy; the minimal covering set is what you actually want to ship. This library computes that set exactly — not an approximation — using a single sort and a forward sweep over integer ranges.

The trade-off: we parse with a hand-rolled tokenizer rather than `ipaddress.ip_network`, because the stdlib constructor rejects host bits being set (e.g. `10.1.2.5/24`). In practice inputs like that are the rule, not the exception, when normalizing messy real-world data. We still use `ipaddress` to validate the address text and to distinguish v4 from v6, so syntactic garbage is rejected — only the host-bit strictness is relaxed.

## Awkward edges

- **v4 and v6 never merge with each other.** An IPv4 block and an IPv6 block may have identical integer representations (e.g. `0.0.0.0/0` and `::/0` both map to `0..max`), but they belong to different families and are merged independently. Mixing them in one call returns the union of two separate merges.
- **Host bits are normalized, not rejected.** `10.0.0.5/24` is treated as `10.0.0.0/24`. If you need strict rejection, validate with `ipaddress.ip_network(strict=True)` before calling.
- **A bare address (no `/`) is treated as `/32` for v4 or `/128` for v6.** This is a deliberate shorthand; if your data uses bare addresses to mean something else, slash-prefix them first.
- **Output is sorted as strings.** Within a family this coincides with numeric order; across families v4 sorts before v6 because digits precede letters in ASCII.

## Running the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```
