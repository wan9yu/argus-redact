# argus-redact-core

[![crates.io](https://img.shields.io/crates/v/argus-redact-core)](https://crates.io/crates/argus-redact-core)
[![docs.rs](https://img.shields.io/docsrs/argus-redact-core)](https://docs.rs/argus-redact-core)
[![License](https://img.shields.io/crates/l/argus-redact-core)](https://github.com/wan9yu/argus-redact/blob/main/LICENSE)

Pure-Rust PII detection and redaction primitives — the core that powers the
[`argus-redact`](https://github.com/wan9yu/argus-redact) Python package.

No PyO3, no Python: just the algorithms. The Python wheel binds to this crate,
and the same core is the foundation for the project's planned C / Swift (iOS) /
WASM targets.

> **Most users want the Python package**, not this crate:
> ```bash
> pip install argus-redact
> ```
> Reach for `argus-redact-core` when you need the primitives directly from Rust,
> or to embed them in a non-Python target.

## What it provides

| Item | Purpose |
|------|---------|
| `match_patterns(text, &[PatternConfig])` | Regex-based PII candidate detection, with optional context check and capture-group extraction |
| `merge_entities(Vec<PatternMatch>)` | Resolve overlapping detections into a non-overlapping span set |
| `restore(text, &HashMap)` | Reverse a redaction using a token → original map |
| `PseudonymGenerator<R: RandomSource>` | Deterministic pseudonym derivation; `RandomSource` lets the caller supply the RNG (the Python binding bridges `random.Random` / `secrets`) |

## Example

```rust
use argus_redact_core::{match_patterns, PatternConfig};

let patterns = vec![PatternConfig {
    type_: "phone".into(),
    pattern: r"1[3-9]\d{9}".into(),
    check_context: false,
    group: None,
}];

let hits = match_patterns("call me at 13812345678", &patterns).unwrap();
assert_eq!(hits[0].text, "13812345678");
assert_eq!(hits[0].type_, "phone");
```

## Versioning

Released lockstep with the `argus-redact` Python package — both share one
version number, so `argus-redact-core` `x.y.z` corresponds to `argus-redact`
`x.y.z`.

## Status

Beta, pre-1.0: the public API may change between minor versions until 1.0.
Detection and pseudonym output are pinned by golden-vector and KDF-replay
tests, so output is bit-stable within a release line.

## License

Apache-2.0. Part of the [argus-redact](https://github.com/wan9yu/argus-redact)
project — see the main repository for the full picture (3-layer detection,
language packs, threat model).
