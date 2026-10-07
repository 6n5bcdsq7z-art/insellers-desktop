//! Private application files are replaced only after a complete, synced write.
use std::{fs::File, io::{self, Write}, path::Path};

pub(crate) fn write_private(path: &Path, value: &str) -> bool {
    write_private_with(path, |file| file.write_all(value.as_bytes())).is_ok()
}

fn write_private_with(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    // NamedTempFile creates a new 0600 file on Unix; Windows inherits the
    // application directory's ACL. Never open/truncate the existing destination.
    let mut pending = tempfile::Builder::new().prefix(".insellers-write-").tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        pending.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    write(pending.as_file_mut())?;
    pending.as_file().sync_all()?;
    // tempfile uses the platform's replace operation; a destination symlink is
    // replaced, not followed. On failure the old file remains and the temp drops.
    pending.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}, thread};

    #[test]
    fn create_and_replace_exact_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        assert!(write_private(&path, "old fixture token"));
        assert!(write_private(&path, "new"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn interrupted_write_preserves_previous_token_and_removes_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        fs::write(&path, "old fixture token").unwrap();
        let result = write_private_with(&path, |file| {
            file.write_all(b"incomplete")?;
            Err(io::Error::other("simulated interrupted write"))
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old fixture token");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_replace_keeps_destination_and_removes_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("occupied");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), "untouched").unwrap();
        assert!(!write_private(&path, "token"));
        assert_eq!(fs::read_to_string(path.join("keep")).unwrap(), "untouched");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn missing_parent_reports_failure_without_creating_directories() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!write_private(&dir.path().join("missing/session.token"), "token"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn readers_never_observe_a_partial_or_missing_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        let old = "a".repeat(4096);
        let new = "b".repeat(8192);
        assert!(write_private(&path, &old));
        let done = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = {
            let path = path.clone(); let done = done.clone(); let reads = reads.clone();
            let old = old.clone(); let new = new.clone();
            thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    let got = fs::read_to_string(&path).expect("destination disappeared");
                    assert!(got == old || got == new, "partial token exposed");
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        while reads.load(Ordering::Relaxed) == 0 { thread::yield_now(); }
        for i in 0..40 {
            assert!(write_private(&path, if i % 2 == 0 { &new } else { &old }));
        }
        done.store(true, Ordering::Release);
        reader.join().unwrap();
        assert!(reads.load(Ordering::Relaxed) > 0);
    }

    #[cfg(unix)]
    #[test]
    fn private_before_writing_and_after_replacing_permissive_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_with(&path, |file| {
            assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
            file.write_all(b"new fixture token")
        }).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_replaced_without_touching_its_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("keep");
        let path = dir.path().join("session.token");
        fs::write(&victim, "untouched").unwrap();
        symlink(&victim, &path).unwrap();
        assert!(write_private(&path, "new fixture token"));
        assert_eq!(fs::read_to_string(victim).unwrap(), "untouched");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new fixture token");
        assert!(!fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
}
