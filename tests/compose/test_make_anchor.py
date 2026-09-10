from argus_redact.compose import Anchor, make_anchor


def test_make_anchor_should_produce_a_fresh_nonce_and_scope_matching_the_key():
    key = {"P-001": "张三", "P-002": "李四"}
    a1 = make_anchor(key)
    a2 = make_anchor(key)
    assert isinstance(a1, Anchor)
    assert a1.scope == frozenset(key)  # scope = the pseudonyms
    assert len(a1.nonce) >= 16  # unpredictable token
    assert a1.nonce != a2.nonce  # fresh per call
    assert isinstance(a1.scope, frozenset)


def test_make_anchor_should_produce_an_empty_scope_when_key_is_empty():
    a = make_anchor({})
    assert a.scope == frozenset() and len(a.nonce) >= 16
