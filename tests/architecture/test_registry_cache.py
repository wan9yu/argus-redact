"""register()/unregister() must invalidate faker-resolution caches."""

from argus_redact.pure.replacer import _registry_generation, _resolve_realistic_faker_cached
from argus_redact.specs import registry


def test_register_clears_faker_cache():
    _resolve_realistic_faker_cached("phone", ("zh",), _registry_generation())  # prime cache
    before = _resolve_realistic_faker_cached.cache_info().currsize
    assert before >= 1
    # a registry mutation must clear the cache
    registry.unregister("zh", "__nonexistent_type__")
    assert _resolve_realistic_faker_cached.cache_info().currsize == 0


def test_registry_mutation_bumps_the_generation():
    """The generation — not the clear — is what makes the cache race-safe: an
    entry inserted by a concurrent in-flight resolve lands under the old
    generation and is never read again."""
    before = _registry_generation()
    registry.unregister("zh", "__nonexistent_type__")
    after = _registry_generation()
    assert after > before


def test_lookup_survives_a_concurrent_registration():
    """``lookup()`` iterated ``_REGISTRY`` itself.

    ``register()``/``unregister()`` are public API callable from any thread, so
    a mutation landing mid-comprehension raised ``RuntimeError: dictionary
    changed size during iteration`` out of the faker-resolution path — i.e. in
    the middle of a redaction, for a caller that did nothing wrong. Iterating a
    snapshot removes the window.
    """
    import sys
    import threading

    from argus_redact.specs.registry import PIITypeDef

    stop = threading.Event()
    errors: list[BaseException] = []

    def churn() -> None:
        i = 0
        while not stop.is_set():
            name = f"__churn_{i % 64}__"
            try:
                registry.register(PIITypeDef(name=name, lang="zz", format="churn"))
                registry.unregister("zz", name)
            except BaseException as e:  # noqa: BLE001 - reported, not swallowed
                errors.append(e)
                return
            i += 1

    # Force the interpreter to preempt inside the comprehension. At the default
    # 5 ms switch interval a scan of the registry finishes in one slice and the
    # window is essentially never hit — the bug would be real and the test
    # green, which is the failure mode this whole finding is about.
    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    t = threading.Thread(target=churn, daemon=True)
    t.start()
    try:
        for _ in range(4000):
            registry.lookup("phone")
            registry.list_types()
            registry.list_types("zh")
    except RuntimeError as e:  # pragma: no cover - the bug this test guards
        errors.append(e)
    finally:
        stop.set()
        t.join(timeout=10)
        sys.setswitchinterval(old_interval)
    assert not errors, errors
