//! Follows a log file through rotation and truncation, one line at a time.

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Longer lines are skipped. Access and fail2ban lines are far shorter.
const MAX_LINE: usize = 16 * 1024;
const CHUNK: u64 = 64 * 1024;

/// Where reading stopped: the file (device and inode) and the byte offset in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub file_id: String,
    pub offset: u64,
}

pub struct Tailer {
    path: PathBuf,
    current: Option<OpenFile>,
    /// Position saved by a previous run, used when the file is first opened.
    resume: Option<Position>,
    /// Never read before: start with the previous file, if there is one, so
    /// a fresh install also gets last week's fail2ban log.
    first_run: bool,
}

struct OpenFile {
    file: File,
    id: String,
    /// Offset just past the last complete line handed out.
    offset: u64,
    /// Inside a line longer than MAX_LINE, waiting for its end.
    skipping: bool,
}

impl Tailer {
    pub fn new(path: PathBuf, resume: Option<Position>) -> Self {
        Self {
            path,
            current: None,
            first_run: resume.is_none(),
            resume,
        }
    }

    pub fn position(&self) -> Option<Position> {
        self.current.as_ref().map(|f| Position {
            file_id: f.id.clone(),
            offset: f.offset,
        })
    }

    /// Returns complete new lines, roughly `max` at most. Empty means nothing new.
    pub fn read_lines(&mut self, max: usize) -> io::Result<Vec<String>> {
        let mut lines = Vec::new();
        if self.current.is_none() && !self.open()? {
            return Ok(lines);
        }
        self.read_into(&mut lines, max)?;
        if lines.is_empty() {
            self.follow_rotation(&mut lines, max)?;
        }
        Ok(lines)
    }

    /// Opens the file, resuming from the saved position when it still applies.
    fn open(&mut self) -> io::Result<bool> {
        if std::mem::take(&mut self.first_run)
            && let Ok(old) = File::open(rotated(&self.path))
        {
            // follow_rotation moves on to the current file afterwards.
            self.current = Some(OpenFile {
                id: file_id(&old.metadata()?),
                file: old,
                offset: 0,
                skipping: false,
            });
            return Ok(true);
        }
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        let id = file_id(&meta);
        let mut opened = OpenFile {
            file,
            id,
            offset: 0,
            skipping: false,
        };

        if let Some(saved) = self.resume.take() {
            if saved.file_id == opened.id && saved.offset <= meta.len() {
                opened.offset = saved.offset;
            } else if let Some(old) = find_rotated(&self.path, &saved.file_id) {
                // Rotated while we were stopped: finish the old file first.
                // follow_rotation moves on to the new one afterwards.
                opened = OpenFile {
                    file: old,
                    id: saved.file_id,
                    offset: saved.offset,
                    skipping: false,
                };
            }
        }
        self.current = Some(opened);
        Ok(true)
    }

    fn read_into(&mut self, lines: &mut Vec<String>, max: usize) -> io::Result<()> {
        let Some(open) = self.current.as_mut() else {
            return Ok(());
        };
        let mut buf = Vec::with_capacity(CHUNK as usize);

        while lines.len() < max {
            buf.clear();
            open.file.seek(SeekFrom::Start(open.offset))?;
            let read = (&open.file).take(CHUNK).read_to_end(&mut buf)?;
            if read == 0 {
                break;
            }

            let mut start = 0;
            if open.skipping {
                match buf.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        start = i + 1;
                        open.skipping = false;
                    }
                    None => {
                        open.offset += read as u64;
                        continue;
                    }
                }
            }

            let Some(end) = buf[start..].iter().rposition(|&b| b == b'\n') else {
                if read - start >= MAX_LINE {
                    open.offset += read as u64;
                    open.skipping = true;
                    continue;
                }
                // Only part of a line so far; wait for the rest.
                open.offset += start as u64;
                break;
            };
            let end = start + end + 1;

            for raw in buf[start..end].split(|&b| b == b'\n') {
                if !raw.is_empty() && raw.len() <= MAX_LINE {
                    let line = String::from_utf8_lossy(raw);
                    lines.push(line.trim_end_matches('\r').to_string());
                }
            }
            open.offset += end as u64;
            if (read as u64) < CHUNK {
                break;
            }
        }
        Ok(())
    }

    /// Switches to the new file after a rotation, or starts over after the
    /// file was truncated in place.
    fn follow_rotation(&mut self, lines: &mut Vec<String>, max: usize) -> io::Result<()> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(meta) => meta,
            // Renamed away and not recreated yet: keep the old file for now.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let Some(open) = self.current.as_mut() else {
            return Ok(());
        };

        if file_id(&meta) != open.id {
            self.current = None;
            if self.open()? {
                self.read_into(lines, max)?;
            }
        } else if meta.len() < open.offset {
            open.offset = 0;
            open.skipping = false;
            self.read_into(lines, max)?;
        }
        Ok(())
    }
}

fn file_id(meta: &Metadata) -> String {
    format!("{}:{}", meta.dev(), meta.ino())
}

/// `access.log.1`, where logrotate puts the previous file.
fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// Opens the rotated copy if it is the file with the given id.
fn find_rotated(path: &Path, id: &str) -> Option<File> {
    let file = File::open(rotated(path)).ok()?;
    let meta = file.metadata().ok()?;
    (file_id(&meta) == id).then_some(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    fn append(path: &Path, text: &str) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn first_start_reads_the_previous_file_too() {
        let (_dir, path) = setup();
        append(&rotated(&path), "last week\n");
        append(&path, "today\n");
        let mut tail = Tailer::new(path.clone(), None);
        assert_eq!(tail.read_lines(10).unwrap(), ["last week"]);
        assert_eq!(tail.read_lines(10).unwrap(), ["today"]);
        assert!(tail.read_lines(10).unwrap().is_empty());
    }

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        (dir, path)
    }

    #[test]
    fn waits_for_the_file_to_appear() {
        let (_dir, path) = setup();
        let mut tail = Tailer::new(path.clone(), None);
        assert!(tail.read_lines(10).unwrap().is_empty());
        append(&path, "one\n");
        assert_eq!(tail.read_lines(10).unwrap(), ["one"]);
    }

    #[test]
    fn holds_back_a_partial_line() {
        let (_dir, path) = setup();
        append(&path, "one\ntw");
        let mut tail = Tailer::new(path.clone(), None);
        assert_eq!(tail.read_lines(10).unwrap(), ["one"]);
        append(&path, "o\n");
        assert_eq!(tail.read_lines(10).unwrap(), ["two"]);
    }

    #[test]
    fn resumes_without_repeating_lines() {
        let (_dir, path) = setup();
        append(&path, "one\ntwo\n");
        let mut tail = Tailer::new(path.clone(), None);
        tail.read_lines(10).unwrap();
        let saved = tail.position();

        append(&path, "three\n");
        let mut restarted = Tailer::new(path.clone(), saved);
        assert_eq!(restarted.read_lines(10).unwrap(), ["three"]);
    }

    #[test]
    fn starts_over_after_truncation() {
        let (_dir, path) = setup();
        append(&path, "one\ntwo\n");
        let mut tail = Tailer::new(path.clone(), None);
        tail.read_lines(10).unwrap();

        std::fs::write(&path, "new\n").unwrap();
        assert_eq!(tail.read_lines(10).unwrap(), ["new"]);
    }

    #[test]
    fn follows_a_rename_rotation() {
        let (dir, path) = setup();
        append(&path, "one\n");
        let mut tail = Tailer::new(path.clone(), None);
        tail.read_lines(10).unwrap();

        // Late write to the old file, then logrotate renames it and a new file starts.
        append(&path, "two\n");
        std::fs::rename(&path, dir.path().join("access.log.1")).unwrap();
        append(&path, "three\n");

        assert_eq!(tail.read_lines(10).unwrap(), ["two"]);
        assert_eq!(tail.read_lines(10).unwrap(), ["three"]);
    }

    #[test]
    fn catches_up_on_a_rotation_that_happened_while_stopped() {
        let (dir, path) = setup();
        append(&path, "one\n");
        let mut tail = Tailer::new(path.clone(), None);
        tail.read_lines(10).unwrap();
        let saved = tail.position();
        drop(tail);

        append(&path, "two\n");
        std::fs::rename(&path, dir.path().join("access.log.1")).unwrap();
        append(&path, "three\n");

        let mut restarted = Tailer::new(path.clone(), saved);
        assert_eq!(restarted.read_lines(10).unwrap(), ["two"]);
        assert_eq!(restarted.read_lines(10).unwrap(), ["three"]);
    }

    #[test]
    fn skips_lines_that_are_too_long() {
        let (_dir, path) = setup();
        append(&path, &format!("{}\nok\n", "x".repeat(MAX_LINE * 5)));
        let mut tail = Tailer::new(path.clone(), None);
        let mut lines = Vec::new();
        for _ in 0..10 {
            lines.extend(tail.read_lines(10).unwrap());
        }
        assert_eq!(lines, ["ok"]);
    }

    #[test]
    fn reads_large_backlogs_in_steps() {
        let (_dir, path) = setup();
        let text: String = (0..5000).map(|i| format!("line {i}\n")).collect();
        append(&path, &text);
        let mut tail = Tailer::new(path.clone(), None);
        let mut total = 0;
        loop {
            let lines = tail.read_lines(1000).unwrap();
            if lines.is_empty() {
                break;
            }
            total += lines.len();
        }
        assert_eq!(total, 5000);
    }
}
