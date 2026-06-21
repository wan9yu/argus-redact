# Performance history (hand-written log)

When `tests/benchmark/baseline.json` is updated, add one line below.

Format:
```
v<from> → v<to>: <workload> <old>ms → <new>ms (<+/-pct>); reason: <why>
```

## v0.6.4

(initial baseline established — no change to record)

---

# Profile log (measured runs)

Entries below are full profiles, not single-line deltas. Every number is labelled
with the machine + Python it was measured on; nothing is hardcoded — re-run the
script to reproduce on your own hardware.

## 2026-06-21 — v0.7.10 L1 (Rust) profile

- Machine: Apple M-series (arm64, macOS)
- Python: 3.11.3
- Build: argus-redact 0.7.10 (Layer-1 detection 100% Rust)
- Reproduce: `python tests/benchmark/bench_l1_rust_vs_python.py`
- Method: `time.perf_counter` p50, warmup before timing. Component A/B 2000
  iterations; throughput 500 iterations. `salt` is a fixed 32-byte value
  (irrelevant to timing).

### Part 1 — component A/B: Rust vs the surviving Python oracle

L1 detection is fully Rust today; two pure-Python oracles survive only for
parity testing (`pure/patterns._match_python_patterns` = real `re.finditer` over
the builtin pattern set; `pure/hints.produce_hints`). Ratio = python_p50 /
rust_p50 (>1 ⇒ Rust faster).

| Component | Python p50 | Rust p50 | Rust speedup |
|-----------|-----------:|---------:|-------------:|
| patterns (en) | 1.007 ms | 0.330 ms | 3.05× |
| patterns (zh) | 0.994 ms | 0.928 ms | 1.07× |
| hints (en)    | 0.0019 ms | 0.0040 ms | 0.47× |
| hints (zh)    | 0.0026 ms | 0.0068 ms | 0.38× |

Coverage caveat — this A/B is the **regex hot path (+ hints) only**. The named
validators (SSN / credit-card Luhn / …) and person-name detection are Rust-only;
no Python oracle survives for them, so they are *not* in these ratios. The Rust
`match_patterns` additionally runs the named validator that the Python oracle
skips (builtin patterns carry a Rust `validator` string, never a Python
`validate` callable), so it does strictly more work per call — the pattern
speedup is a conservative lower bound for the regex+context portion.

Hints honesty note — Rust is *slower* than Python for the hint producer at this
scale. The producer is a ~2–7 µs workload; crossing the PyO3 boundary costs more
than the few-element Python loop. In production this is harmless (hints run once
per call against a sub-millisecond detection), but it is a real, reproducible
result, recorded as-is rather than hidden.

### Part 2 — cross-version end-to-end A/B (migration-era delta)

`redact(text, mode="fast")` on the ~1KB corpus, v0.6.12 vs v0.7.10, identical
corpus + iteration count. v0.6.12 was installed into an isolated venv from a
transient worktree; v0.7.10 is the current build. Both versions were confirmed
by `__version__` + `__file__` at measure time.

| Corpus | v0.6.12 | v0.7.10 | speedup |
|--------|--------:|--------:|--------:|
| en ~1KB | ~1,205 docs/s (0.83 ms) | ~1,252 docs/s (0.80 ms) | ~1.04× |
| zh ~1KB | ~571 docs/s (1.75 ms) | ~684 docs/s (1.46 ms) | ~1.20× |

Caveat — this is **not** a same-logic engine swap. v0.6.12 already shipped a
partial Rust core (`match_patterns` / `merge` / `restore` / `pseudonym` in Rust);
v0.7.x moved the rest of the L1 orchestration (normalize → hints → person → the
`detect_l1` sequence) into Rust *and* broadened detection coverage + added
validators. Read this as the migration-era end-to-end change, not a pure
before/after of one engine. The near-flat en result reflects that the en regex
hot path was already Rust at 0.6.12; zh gains more from the orchestration moving
across the boundary.

### Part 3 — current throughput profile (v0.7.10, mode="fast")

p50 over 500 iterations; `detect_l1` is the raw Rust L1 call (no
pseudonym/replace), `redact` is the full fast-mode path.

| Input | bytes | redact() p50 | redact docs/s | detect_l1 p50 | detect_l1 docs/s |
|-------|------:|-------------:|--------------:|--------------:|-----------------:|
| en short | 141 | 0.19 ms | ~5,140 | 0.12 ms | ~8,200 |
| en ~1KB  | 846 | 0.80 ms | ~1,250 | 0.67 ms | ~1,490 |
| en long  | 8460 | 7.85 ms | ~127 | 6.90 ms | ~145 |
| zh short | 175 | 0.27 ms | ~3,730 | 0.18 ms | ~5,690 |
| zh ~1KB  | 1400 | 1.47 ms | ~681 | 1.27 ms | ~790 |
| zh long  | 14000 | 14.65 ms | ~68 | 13.07 ms | ~77 |

Doc-corpus reconciliation (README / benchmark-report) — measured the exact
README/benchmark-report corpus sizes (en, same machine/Python): short 17 chars
≈ 0.034 ms (~29,000 docs/s); medium 770 chars ≈ 0.74 ms (~1,350 docs/s); long
10K chars ≈ 9.3 ms (~107 docs/s). Both docs previously disagreed (README long
22.2 ms / benchmark-report long 4.84 ms; README short 13,036 docs/s /
benchmark-report short 36,353 docs/s); both were stale and have been reconciled
to these measured values.
