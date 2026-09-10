// Shared build-time source hasher, included into `build.rs` via `#[path]`.
// The recipe MUST match `tests/architecture/test_version_parity.py::_source_hash`
// byte-for-byte: `build.rs::main` asserts a fixed test vector against a hash
// pasted from that Python recipe as a build-time proof the two independent
// implementations agree (cargo never compiles or runs `#[test]` inside a
// build script, so this cannot be a normal unit test).
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

// The hashed source set, declared once. `build.rs` also iterates these for
// `cargo:rerun-if-changed`, so the set of files that feeds the hash and the set
// that triggers a rebuild cannot drift apart. Mirrored on the Python side by
// SOURCE_DIRS/EXTRA_FILES in tests/architecture/test_version_parity.py.
pub const SOURCE_DIRS: [&str; 3] = [
    "crates/argus-redact-core/src",
    "crates/argus-redact-core/data",
    "crates/argus-redact-py/src",
];
pub const EXTRA_FILES: [&str; 4] = [
    "Cargo.lock",
    "Cargo.toml",
    "crates/argus-redact-core/Cargo.toml",
    "crates/argus-redact-py/Cargo.toml",
];

pub fn source_hash(repo_root: &Path) -> Option<String> {
    if !repo_root.join(SOURCE_DIRS[0]).exists() {
        return None; // sdist/wheel: no source tree
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for d in SOURCE_DIRS {
        collect(&repo_root.join(d), &mut files);
    }
    for f in EXTRA_FILES {
        let p = repo_root.join(f);
        if p.exists()
            && !p
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true)
        {
            files.push(p);
        }
    }
    // Read each file once, keyed by its repo-root-relative, `/`-normalised path.
    let owned: Vec<(String, Vec<u8>)> = files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(repo_root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, fs::read(&p).unwrap())
        })
        .collect();
    let pairs: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(r, b)| (r.as_str(), b.as_slice()))
        .collect();
    Some(hash_keyed(pairs))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let ft = entry.file_type().unwrap();
        if ft.is_symlink() {
            continue; // do not follow symlinks (Python uses os.walk(followlinks=False))
        }
        let p = entry.path();
        if ft.is_dir() {
            collect(&p, out);
        } else if matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("rs") | Some("ron")
        ) {
            out.push(p);
        }
    }
}

/// The single canonical digest recipe: sort `(relpath, content)` pairs bytewise
/// on the UTF-8 relpath, then feed `relpath \0 content` for each into one
/// sha256. Both `source_hash` (live tree) and `source_hash_of_files` (fixed
/// vector) go through here so the recipe lives in exactly one place.
fn hash_keyed(mut items: Vec<(&str, &[u8])>) -> String {
    items.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes())); // bytewise on UTF-8 relpath
    let mut h = Sha256::new();
    for (rel, content) in items {
        h.update(rel.as_bytes());
        h.update(b"\0");
        h.update(content);
    }
    // Lowercase, zero-padded, two-hex-digits-per-byte, in digest order — the
    // exact bytes `format!("{:x}", …)` produced under generic-array's LowerHex
    // (digest 0.11's `Array` no longer impls LowerHex). Kept manual so the baked
    // source-hash string is byte-for-byte stable across the crypto crate bump.
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// Hashes an in-memory (relpath, content) set with the canonical recipe, used
/// to hash the fixed test vector below.
pub fn source_hash_of_files(files: &[(&str, &[u8])]) -> String {
    hash_keyed(files.to_vec())
}

/// Fixed tiny tree with known bytes, hashed by the same recipe as `source_hash`.
/// `build.rs` asserts this hashes to `VECTOR_EXPECTED` at build time, and
/// `tests/architecture/test_version_parity.py::test_shared_vector_agrees`
/// asserts the same constant against its own Python implementation — proving
/// the two recipes agree independent of the live checkout's contents.
pub const VECTOR_FILES: [(&str, &[u8]); 3] =
    [("a.rs", b"alpha"), ("b/c.ron", b"beta"), ("z.rs", b"gamma")];
pub const VECTOR_EXPECTED: &str =
    "b5a7a18b4257178108b7b7f17030063393be16e8e8106a6d405634a344a896e4";
