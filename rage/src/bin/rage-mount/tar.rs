use age::{armor::ArmoredReader, stream::StreamReader};
use fuse_mt::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tar::{Archive, Entry, EntryType};
use time::Timespec;

fn tar_path(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap()
}

fn tar_to_filetype<R: Read>(entry: &Entry<R>) -> Option<FileType> {
    // Only map filetypes we support
    match entry.header().entry_type() {
        EntryType::Regular => Some(FileType::RegularFile),
        EntryType::Directory => Some(FileType::Directory),
        EntryType::Continuous => Some(FileType::RegularFile),
        EntryType::GNULongName => Some(FileType::RegularFile),
        _ => None,
    }
}

fn tar_to_fuse<R: Read>(entry: &Entry<R>) -> io::Result<FileAttr> {
    let kind = tar_to_filetype(entry)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Unsupported filetype"))?;
    let perm = (entry.header().mode()? & 0o7777) as u16;

    let mtime = Timespec::new(entry.header().mtime()? as i64, 0);
    let ctime = if let Some(header) = entry.header().as_gnu() {
        header
            .ctime()
            .map(|ctime| Timespec::new(ctime as i64, 0))
            .unwrap_or(mtime)
    } else {
        mtime
    };
    let atime = if let Some(header) = entry.header().as_gnu() {
        header
            .atime()
            .map(|atime| Timespec::new(atime as i64, 0))
            .unwrap_or(mtime)
    } else {
        mtime
    };

    Ok(FileAttr {
        size: entry.header().size()?,
        blocks: 1,
        atime,
        mtime,
        ctime,
        crtime: Timespec { sec: 0, nsec: 0 },
        kind,
        perm,
        nlink: 1,
        uid: entry.header().uid()? as u32,
        gid: entry.header().gid()? as u32,
        rdev: 0,
        flags: 0,
    })
}

const ROOT_ATTR: FileAttr = FileAttr {
    size: 0,
    blocks: 0,
    atime: Timespec { sec: 0, nsec: 0 },
    mtime: Timespec { sec: 0, nsec: 0 },
    ctime: Timespec { sec: 0, nsec: 0 },
    crtime: Timespec { sec: 0, nsec: 0 },
    kind: FileType::Directory,
    perm: 0o0755,
    nlink: 1,
    uid: 1000,
    gid: 1000,
    rdev: 0,
    flags: 0,
};

fn add_to_dir_map(
    dir_map: &mut HashMap<PathBuf, Vec<DirectoryEntry>>,
    path: &Path,
    kind: FileType,
) {
    let name = path
        .file_name()
        .expect("All files in tarballs have names")
        .to_owned();

    let parent = path
        .parent()
        .expect("paths should have parents")
        .to_path_buf();

    // tar files are listed in-order, so the parent has already been added.
    dir_map
        .entry(parent)
        .or_default()
        .push(DirectoryEntry { name, kind });
}

type OpenFile = (PathBuf, u64, u64);

pub struct AgeTarFs {
    inner: Mutex<StreamReader<ArmoredReader<BufReader<File>>>>,
    dir_map: HashMap<PathBuf, Vec<DirectoryEntry>>,
    file_map: HashMap<PathBuf, (FileAttr, u64)>,
    open_dirs: Mutex<(HashMap<u64, PathBuf>, u64)>,
    open_files: Mutex<(HashMap<u64, OpenFile>, u64)>,
}

impl AgeTarFs {
    pub fn open(stream: StreamReader<ArmoredReader<BufReader<File>>>) -> io::Result<Self> {
        // Build a directory listing for the archive
        let mut dir_map: HashMap<PathBuf, Vec<DirectoryEntry>> = HashMap::new();
        dir_map.insert(PathBuf::new(), vec![]); // the root

        // Build a file map for the archive
        let mut file_map: HashMap<PathBuf, (FileAttr, u64)> = HashMap::new();

        let mut archive = Archive::new(stream);
        for file in archive.entries().expect("StreamReader is at start") {
            let file = file?;
            if let Some(filetype) = tar_to_filetype(&file) {
                let path = file.path()?;
                add_to_dir_map(&mut dir_map, &path, filetype);
                file_map.insert(
                    path.to_path_buf(),
                    (tar_to_fuse(&file)?, file.raw_file_position()),
                );
            }
        }

        Ok(AgeTarFs {
            inner: Mutex::new(archive.into_inner()),
            dir_map,
            file_map,
            open_dirs: Mutex::new((HashMap::new(), 0)),
            open_files: Mutex::new((HashMap::new(), 0)),
        })
    }
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

impl FilesystemMT for AgeTarFs {
    fn getattr(&self, _req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        let open_dirs = self.open_dirs.lock().unwrap();
        let open_files = self.open_files.lock().unwrap();

        if let Some(fh) = fh {
            if let Some((attr, _)) = open_dirs
                .0
                .get(&fh)
                .and_then(|path| self.file_map.get(path))
            {
                Ok((TTL, *attr))
            } else if let Some((attr, _)) = open_files
                .0
                .get(&fh)
                .and_then(|(path, _, _)| self.file_map.get(path))
            {
                Ok((TTL, *attr))
            } else {
                Err(libc::EBADF)
            }
        } else {
            let path = tar_path(path);
            if path.parent().is_none() {
                Ok((TTL, ROOT_ATTR))
            } else if let Some((attr, _)) = self.file_map.get(path) {
                Ok((TTL, *attr))
            } else {
                Err(libc::ENOENT)
            }
        }
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let mut open_dirs = self.open_dirs.lock().unwrap();

        let fh = open_dirs.1;
        let path = tar_path(path);

        open_dirs.0.insert(fh, path.to_path_buf());
        open_dirs.1 = open_dirs.1.wrapping_add(1);

        Ok((fh, 0))
    }

    fn readdir(&self, _req: RequestInfo, _path: &Path, fh: u64) -> ResultReaddir {
        let open_dirs = self.open_dirs.lock().unwrap();

        if let Some(path) = open_dirs.0.get(&fh) {
            Ok(self.dir_map.get(path).cloned().unwrap_or_default())
        } else {
            Err(libc::EBADF)
        }
    }

    fn releasedir(&self, _req: RequestInfo, _path: &Path, fh: u64, _flags: u32) -> ResultEmpty {
        let mut open_dirs = self.open_dirs.lock().unwrap();

        open_dirs.0.remove(&fh).map(|_| ()).ok_or(libc::EBADF)
    }

    fn statfs(&self, _req: RequestInfo, _path: &Path) -> ResultStatfs {
        Ok(Statfs {
            blocks: self.file_map.len() as u64,
            bfree: 0,
            bavail: 0,
            files: self.file_map.len() as u64,
            ffree: 0,
            bsize: 64 * 1024,
            namelen: u32::max_value(),
            frsize: 64 * 1024,
        })
    }

    fn open(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let mut open_files = self.open_files.lock().unwrap();

        if let Some((attr, pos)) = self.file_map.get(tar_path(path)) {
            let fh = open_files.1;
            open_files
                .0
                .insert(fh, (path.to_path_buf(), *pos, attr.size));
            open_files.1 = open_files.1.wrapping_add(1);
            Ok((fh, 0))
        } else {
            Err(libc::ENOENT)
        }
    }

    fn read(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult,
    ) -> CallbackResult {
        let mut inner = self.inner.lock().unwrap();
        let open_files = self.open_files.lock().unwrap();

        if let Some((_, pos, file_size)) = open_files.0.get(&fh) {
            if offset > *file_size {
                return callback(Err(libc::EINVAL));
            }

            // Skip to offset
            if inner.seek(SeekFrom::Start(pos + offset)).is_err() {
                return callback(Err(libc::EIO));
            }

            // Read bytes
            let to_read = usize::min(size as usize, (file_size - offset) as usize);
            let mut buf = vec![];
            buf.resize(to_read, 0);
            match inner.read_exact(&mut buf) {
                Ok(_) => callback(Ok(&buf)),
                Err(_) => callback(Err(libc::EIO)),
            }
        } else {
            callback(Err(libc::EBADF))
        }
    }

    fn release(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> ResultEmpty {
        let mut open_files = self.open_files.lock().unwrap();

        open_files.0.remove(&fh).map(|_| ()).ok_or(libc::EBADF)
    }
}
