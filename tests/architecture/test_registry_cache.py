"""register()/unregister() must invalidate faker-resolution caches."""

from argus_redact.pure.replacer import _resolve_realistic_faker_cached
from argus_redact.specs import registry


def test_register_clears_faker_cache():
    _resolve_realistic_faker_cached("phone", ("zh",))  # prime cache
    before = _resolve_realistic_faker_cached.cache_info().currsize
    assert before >= 1
    # a registry mutation must clear the cache
    registry.unregister("zh", "__nonexistent_type__")
    assert _resolve_realistic_faker_cached.cache_info().currsize == 0
