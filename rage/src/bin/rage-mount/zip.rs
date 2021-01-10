use age::{armor::ArmoredReader, stream::StreamReader};
use fuse_mt::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::Timespec;
use zip::{read::ZipFile, ZipArchive};

fn zip_path(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap()
}

fn zipfile_to_filetype(zf: &ZipFile) -> FileType {
    if zf.is_dir() {
        FileType::Directory
    } else {
        FileType::RegularFile
    }
}

fn zipfile_to_fuse(zf: &ZipFile) -> FileAttr {
    let kind = zipfile_to_filetype(zf);
    let perm = (zf.unix_mode().unwrap_or(0) & 0o7777) as u16;
    let mtime = zf.last_modified().to_time().to_timespec();

    FileAttr {
        size: zf.size() as u64,
        blocks: 1,
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: Timespec { sec: 0, nsec: 0 },
        kind,
        perm,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        flags: 0,
    }
}

const DIR_ATTR: FileAttr = FileAttr {
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

fn add_dir_to_map(
    dir_map: &mut HashMap<PathBuf, Vec<DirectoryEntry>>,
    path: &Path,
    kind: FileType,
) {
    let name = path
        .file_name()
        .expect("All ZIP files have filenames")
        .to_owned();

    let parent = path
        .parent()
        .expect("paths should have parents")
        .to_path_buf();

    if !dir_map.contains_key(&parent) {
        add_dir_to_map(dir_map, &parent, FileType::Directory);
    }

    dir_map
        .entry(parent)
        .or_default()
        .push(DirectoryEntry { name, kind });
}

pub struct AgeZipFs {
    inner: Mutex<ZipArchive<StreamReader<ArmoredReader<BufReader<File>>>>>,
    dir_map: HashMap<PathBuf, Vec<DirectoryEntry>>,
    open_dirs: Mutex<(HashMap<u64, PathBuf>, u64)>,
    open_files: Mutex<(HashMap<u64, usize>, u64)>,
}

impl AgeZipFs {
    pub fn open(stream: StreamReader<ArmoredReader<BufReader<File>>>) -> io::Result<Self> {
        let mut archive =
            ZipArchive::new(stream).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Build a directory listing for the archive
        let mut dir_map: HashMap<PathBuf, Vec<DirectoryEntry>> = HashMap::new();
        dir_map.insert(PathBuf::new(), vec![]); // the root
        for i in 0..archive.len() {
            let zf = archive
                .by_index(i)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            if let Some(path) = zf.enclosed_name() {
                add_dir_to_map(&mut dir_map, path, zipfile_to_filetype(&zf));
            }
        }

        Ok(AgeZipFs {
            inner: Mutex::new(archive),
            dir_map,
            open_dirs: Mutex::new((HashMap::new(), 0)),
            open_files: Mutex::new((HashMap::new(), 0)),
        })
    }
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

impl FilesystemMT for AgeZipFs {
    fn getattr(&self, _req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        let mut inner = self.inner.lock().unwrap();
        let open_dirs = self.open_dirs.lock().unwrap();
        let open_files = self.open_files.lock().unwrap();

        if let Some(fh) = fh {
            if open_dirs.0.contains_key(&fh) {
                Ok((TTL, DIR_ATTR))
            } else if let Some(index) = open_files.0.get(&fh) {
                let zf = inner.by_index(*index).expect("open_files is correct");
                Ok((TTL, zipfile_to_fuse(&zf)))
            } else {
                Err(libc::EBADF)
            }
        } else if self.dir_map.contains_key(zip_path(path)) {
            Ok((TTL, DIR_ATTR))
        } else {
            match inner.by_name(zip_path(path).to_str().unwrap()) {
                Ok(zf) => Ok((TTL, zipfile_to_fuse(&zf))),
                Err(_) => Err(libc::ENOENT),
            }
        }
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let mut open_dirs = self.open_dirs.lock().unwrap();

        let fh = open_dirs.1;
        let path = zip_path(path);

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
        let inner = self.inner.lock().unwrap();

        Ok(Statfs {
            blocks: inner.len() as u64,
            bfree: 0,
            bavail: 0,
            files: inner.len() as u64,
            ffree: 0,
            bsize: 64 * 1024,
            namelen: u32::max_value(),
            frsize: 64 * 1024,
        })
    }

    fn open(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let mut inner = self.inner.lock().unwrap();
        let mut open_files = self.open_files.lock().unwrap();

        for i in 0..inner.len() {
            if inner.by_index(i).unwrap().enclosed_name() == Some(zip_path(path)) {
                let fh = open_files.1;
                open_files.0.insert(fh, i);
                open_files.1 = open_files.1.wrapping_add(1);
                return Ok((fh, 0));
            }
        }

        Err(libc::ENOENT)
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

        match open_files.0.get(&fh) {
            Some(index) => {
                let mut zf = inner.by_index(*index).expect("open_files is correct");
                if offset > zf.size() {
                    return callback(Err(libc::EINVAL));
                }

                // Skip to offset
                let mut buf = vec![];
                buf.resize(offset as usize, 0);
                if zf.read_exact(&mut buf).is_err() {
                    return callback(Err(libc::EIO));
                }

                // Read bytes
                let to_read = usize::min(size as usize, (zf.size() - offset) as usize);
                buf.resize(to_read, 0);
                match zf.read_exact(&mut buf) {
                    Ok(_) => callback(Ok(&buf)),
                    Err(_) => callback(Err(libc::EIO)),
                }
            }
            None => callback(Err(libc::EBADF)),
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
