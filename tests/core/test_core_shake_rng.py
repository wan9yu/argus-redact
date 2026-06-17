import argus_redact._core as _core


def test_core_shakerng_matches_python_shakerng_randint_stream():
    from argus_redact.pure.replacer import _ShakeRng  # still present at this task
    seed = b"v0.7.4-shakerng-parity-seed-0001"
    py = _ShakeRng(seed=seed)
    rs = _core.ShakeRng(seed)
    for _ in range(40):
        assert rs.randint(0, 9) == py.randint(0, 9)
    for hi in (255, 1000, 7):
        assert rs.randint(0, hi) == py.randint(0, hi)


def test_core_shakerng_choice_matches():
    seed = b"choice-parity-seed-padding-00001"
    from argus_redact.pure.replacer import _ShakeRng
    py = _ShakeRng(seed=seed)
    rs = _core.ShakeRng(seed)
    pool = ["a", "b", "c", "d", "e"]
    for _ in range(20):
        assert rs.choice(pool) == py.choice(pool)
