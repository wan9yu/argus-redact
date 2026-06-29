"""v0.7.0 C0: golden vectors locking the PseudonymGenerator RNG call sequence.

Captured from main BEFORE the workspace split + RandomSource trait refactor.
If C4 changes the bit stream, these fail. Entity ORDER matters because the RNG
is consumed per generate_unique() call.
"""

import pytest

from argus_redact.pure.pseudonym import PseudonymGenerator

# [seed, prefix, code_range, entities, expected_codes]
GOLDEN = [
    [
        42,
        "P",
        [1, 99999],
        ["Alice", "Bob", "Alice", "Carol", "Dave"],
        ["P-83811", "P-14593", "P-83811", "P-03279", "P-97197"],
    ],
    [
        42,
        "P",
        [1, 99999],
        ["张三", "李四", "王五", "张三"],
        ["P-83811", "P-14593", "P-03279", "P-83811"],
    ],
    [
        42,
        "P",
        [1, 99999],
        ["x", "y", "z", "x", "y", "w", "v"],
        ["P-83811", "P-14593", "P-03279", "P-83811", "P-14593", "P-97197", "P-36049"],
    ],
    [
        7,
        "P",
        [1, 99999],
        ["Alice", "Bob", "Alice", "Carol", "Dave"],
        ["P-42446", "P-19773", "P-42446", "P-51751", "P-85320"],
    ],
    [
        7,
        "P",
        [1, 99999],
        ["张三", "李四", "王五", "张三"],
        ["P-42446", "P-19773", "P-51751", "P-42446"],
    ],
    [
        7,
        "P",
        [1, 99999],
        ["x", "y", "z", "x", "y", "w", "v"],
        ["P-42446", "P-19773", "P-51751", "P-42446", "P-19773", "P-85320", "P-06329"],
    ],
    [
        42,
        "ORG",
        [1, 99999],
        ["Alice", "Bob", "Alice", "Carol", "Dave"],
        ["ORG-83811", "ORG-14593", "ORG-83811", "ORG-03279", "ORG-97197"],
    ],
    [
        42,
        "ORG",
        [1, 99999],
        ["张三", "李四", "王五", "张三"],
        ["ORG-83811", "ORG-14593", "ORG-03279", "ORG-83811"],
    ],
    [
        42,
        "ORG",
        [1, 99999],
        ["x", "y", "z", "x", "y", "w", "v"],
        ["ORG-83811", "ORG-14593", "ORG-03279", "ORG-83811", "ORG-14593", "ORG-97197", "ORG-36049"],
    ],
    [
        123,
        "M",
        [1, 9999],
        ["Alice", "Bob", "Alice", "Carol", "Dave"],
        ["M-00858", "M-04386", "M-00858", "M-01429", "M-06673"],
    ],
    [
        123,
        "M",
        [1, 9999],
        ["张三", "李四", "王五", "张三"],
        ["M-00858", "M-04386", "M-01429", "M-00858"],
    ],
    [
        123,
        "M",
        [1, 9999],
        ["x", "y", "z", "x", "y", "w", "v"],
        ["M-00858", "M-04386", "M-01429", "M-00858", "M-04386", "M-06673", "M-04368"],
    ],
    [
        0,
        "P",
        [1, 99999],
        ["Alice", "Bob", "Alice", "Carol", "Dave"],
        ["P-50495", "P-99347", "P-50495", "P-55126", "P-05307"],
    ],
    [
        0,
        "P",
        [1, 99999],
        ["张三", "李四", "王五", "张三"],
        ["P-50495", "P-99347", "P-55126", "P-50495"],
    ],
    [
        0,
        "P",
        [1, 99999],
        ["x", "y", "z", "x", "y", "w", "v"],
        ["P-50495", "P-99347", "P-55126", "P-50495", "P-99347", "P-05307", "P-33937"],
    ],
]


@pytest.mark.parametrize("seed,prefix,code_range,entities,expected", GOLDEN)
def test_pseudonym_golden(seed, prefix, code_range, entities, expected):
    g = PseudonymGenerator(prefix=prefix, code_range=tuple(code_range), seed=seed)
    actual = [g.get(e) for e in entities]
    assert actual == expected, (
        f"pseudonym RNG stream changed for seed={seed} prefix={prefix}.\n"
        f"  expected: {expected}\n  actual:   {actual}\n"
        f"If this fires during the C4 RandomSource refactor, the trait method "
        f"mapping diverged from Python random.Random — fix the mapping, do NOT "
        f"update the vectors."
    )
