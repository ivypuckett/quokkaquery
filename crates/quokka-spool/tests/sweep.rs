//! Ephemerality (§4.1): a spool dies with its process, an orphan is swept, and — the
//! thing that matters most — a *live* process's spool is left alone.
//!
//! The trap this file exists for: PIDs are reused, so "the owning PID is no longer
//! alive" is not the same question as "is this an orphan", and a sweep that gets it
//! wrong deletes the rows under somebody's open result. So the sweep asks whether the
//! directory's lock is still held, and these tests hold one.

use quokka_spool::{sweep, Limits, SpoolSet};

#[tokio::test]
async fn the_sweep_leaves_a_live_process_s_spool_alone() {
    let root = tempfile::tempdir().unwrap();

    // A spool set that is still running, with a result in it.
    let live = SpoolSet::open(Some(root.path()), Limits::default())
        .await
        .unwrap();
    let live_dir = live.dir().to_path_buf();
    std::fs::write(live_dir.join("result.db"), b"rows").unwrap();

    // A second sweep of the same root — what the next `quokka` invocation does at
    // startup while this one is still running.
    let removed = sweep(root.path()).await;

    assert!(
        removed.is_empty(),
        "the sweep removed a live spool directory: {removed:?}"
    );
    assert!(live_dir.exists(), "a running process lost its spool");
    assert!(live_dir.join("result.db").exists());

    live.close().await;
}

#[tokio::test]
async fn an_orphan_left_by_a_crash_is_swept() {
    let root = tempfile::tempdir().unwrap();

    let crashed = SpoolSet::open(Some(root.path()), Limits::default())
        .await
        .unwrap();
    let orphan = crashed.dir().to_path_buf();
    std::fs::write(orphan.join("result.db"), b"rows").unwrap();
    // A crash: the lock goes, the files stay. Which is what the operating system does
    // for a process that dies however it dies.
    let abandoned = crashed.abandon().await;
    assert_eq!(abandoned, orphan);
    assert!(orphan.exists());

    let next = SpoolSet::open(Some(root.path()), Limits::default())
        .await
        .unwrap();

    assert!(
        next.swept().contains(&orphan),
        "startup did not sweep the orphan; it swept {:?}",
        next.swept()
    );
    assert!(!orphan.exists());
    assert!(next.dir().exists(), "the sweep took the new spool with it");

    next.close().await;
}

#[tokio::test]
async fn a_clean_exit_leaves_nothing_behind() {
    let root = tempfile::tempdir().unwrap();

    let spools = SpoolSet::open(Some(root.path()), Limits::default())
        .await
        .unwrap();
    let dir = spools.dir().to_path_buf();
    let writer = spools.writer(uuid::Uuid::now_v7(), "app").unwrap();
    let spool_file = writer.path().to_path_buf();
    drop(writer);
    assert!(spool_file.exists());

    spools.close().await;

    assert!(!dir.exists(), "the spool directory survived a clean exit");
    // Nothing accumulates: the cache directory never holds query results between runs
    // (§4.1), so the data-handling story stays "we don't keep them".
    let left: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert!(left.is_empty(), "the cache still holds {left:?}");
}

#[tokio::test]
async fn two_spool_sets_do_not_share_a_directory() {
    let root = tempfile::tempdir().unwrap();

    // Same process, so the same PID — which is exactly why the directory name carries
    // more than the PID.
    let first = SpoolSet::open(Some(root.path()), Limits::default())
        .await
        .unwrap();
    let second = SpoolSet::open(Some(root.path()), Limits::default())
        .await
        .unwrap();

    assert_ne!(first.dir(), second.dir());
    assert!(first.dir().exists() && second.dir().exists());
    // Neither swept the other.
    assert!(first.swept().is_empty());
    assert!(second.swept().is_empty());

    first.close().await;
    assert!(second.dir().exists());
    second.close().await;
}

/// The cache directory, not `/tmp` — §4.1 is explicit, because `/tmp` is tmpfs on many
/// systems and a 1 GiB spool would land in RAM.
#[test]
fn spools_live_under_the_cache_directory() {
    let dir = tempfile::tempdir().unwrap();
    // Safety: this test does not spawn threads, and it restores nothing because each
    // test binary gets its own process.
    unsafe { std::env::set_var("QUOKKA_CACHE_DIR", dir.path()) };
    let root = quokka_spool::default_spool_root().unwrap();
    assert!(root.starts_with(dir.path()));
    assert!(
        !root.starts_with(std::env::temp_dir()) || dir.path().starts_with(std::env::temp_dir())
    );
}
