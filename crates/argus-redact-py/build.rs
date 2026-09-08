#[path = "build_hash.rs"]
mod build_hash;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // crates/argus-redact-py
    let repo_root = manifest.parent().unwrap().parent().unwrap().to_path_buf();

    // Shared test vector: proves this hasher agrees with the Python recipe in
    // tests/architecture/test_version_parity.py::test_shared_vector_agrees,
    // independent of the live checkout's contents.
    assert_eq!(
        build_hash::source_hash_of_files(&build_hash::VECTOR_FILES),
        build_hash::VECTOR_EXPECTED,
        "build_hash recipe drift"
    );

    let version = env!("CARGO_PKG_VERSION");
    let build = match build_hash::source_hash(&repo_root) {
        Some(h) => format!("{version}+{h}"),
        None => format!("{version}+unknown"),
    };
    println!("cargo:rustc-env=ARGUS_BUILD={build}");

    for d in build_hash::SOURCE_DIRS
        .iter()
        .chain(build_hash::EXTRA_FILES.iter())
    {
        println!("cargo:rerun-if-changed={}", repo_root.join(d).display());
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_hash.rs");
}
