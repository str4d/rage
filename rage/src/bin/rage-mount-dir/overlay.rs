use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use age::Identity;
use fuse_mt::*;
use nix::{dir::Dir, fcntl::OFlag, libc, sys::stat::Mode, unistd::AccessFlags};
use time::Timespec;

use crate::{
    reader::OpenedFile,
    util::*,
    wrapper::{check_file, AgeFile},
};

pub struct AgeOverlayFs {
    root: PathBuf,
    identities: Vec<Box<dyn Identity + Send + Sync>>,
    age_files: Mutex<HashMap<PathBuf, (PathBuf, Option<AgeFile>)>>,
    open_dirs: Mutex<HashMap<u64, Dir>>,
    open_files: Mutex<HashMap<u64, OpenedFile>>,
}

impl AgeOverlayFs {
    pub fn new(
        root: PathBuf,
        identities: Vec<Box<dyn Identity + Send + Sync>>,
    ) -> io::Result<Self> {
        // TODO: Scan the directory to find age-encrypted files, and trial-decrypt them.
        // We'll do this manually in order to cache the unwrapped FileKeys for X? minutes.

        Ok(AgeOverlayFs {
            root,
            identities,
            age_files: Mutex::new(HashMap::new()),
            open_dirs: Mutex::new(HashMap::new()),
            open_files: Mutex::new(HashMap::new()),
        })
    }

    fn base_path(&self, path: &Path) -> PathBuf {
        self.root.join(path.strip_prefix("/").unwrap())
    }

    fn age_stat(&self, f: &AgeFile, mut stat: FileAttr) -> FileAttr {
        stat.size = f.size;
        stat
    }
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

impl FilesystemMT for AgeOverlayFs {
    fn getattr(&self, _req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        let age_files = self.age_files.lock().unwrap();
        let base_path = self.base_path(path);
        let (query_path, age_file) = match age_files.get(&base_path) {
            Some((real_path, Some(f))) => (real_path, Some(f)),
            _ => (&base_path, None),
        };

        use std::os::unix::io::RawFd;
        nix_err(if let Some(fd) = fh {
            nix::sys::stat::fstat(fd as RawFd)
        } else {
            nix::sys::stat::lstat(query_path)
        })
        .map(nix_stat)
        .map(|stat| {
            if let Some(f) = age_file {
                self.age_stat(f, stat)
            } else {
                stat
            }
        })
        .map(|stat| (TTL, stat))
    }

    fn chmod(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _mode: u32) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn chown(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _uid: Option<u32>,
        _gid: Option<u32>,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn truncate(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _size: u64,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn utimens(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _atime: Option<Timespec>,
        _mtime: Option<Timespec>,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    #[allow(clippy::too_many_arguments)]
    fn utimens_macos(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _crtime: Option<Timespec>,
        _chgtime: Option<Timespec>,
        _bkuptime: Option<Timespec>,
        _flags: Option<u32>,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn readlink(&self, _req: RequestInfo, path: &Path) -> ResultData {
        use std::os::unix::ffi::OsStringExt;
        nix_err(nix::fcntl::readlink(&self.base_path(path))).map(|s| s.into_vec())
    }

    fn mknod(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _rdev: u32,
    ) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn mkdir(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _mode: u32) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn unlink(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn rmdir(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn symlink(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _target: &Path,
    ) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn rename(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _newparent: &Path,
        _newname: &OsStr,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn link(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _newparent: &Path,
        _newname: &OsStr,
    ) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn open(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let age_files = self.age_files.lock().unwrap();
        let base_path = self.base_path(path);
        let file = match age_files.get(&base_path) {
            Some((real_path, Some(f))) => OpenedFile::age(real_path, f),
            _ => OpenedFile::normal(&base_path),
        }
        .map_err(|e| e.raw_os_error().unwrap_or(0))?;
        let fh = file.handle();

        let mut open_files = self.open_files.lock().unwrap();
        open_files.insert(fh, file);

        Ok((fh, 0))
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
        let mut open_files = self.open_files.lock().unwrap();
        let mut buf = vec![0; size as usize];
        callback(open_files.get_mut(&fh).ok_or(libc::EBADF).and_then(|file| {
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| file.read(&mut buf))
                .map(|bytes| &buf[..bytes])
                .map_err(|e| e.raw_os_error().unwrap_or(0))
        }))
    }

    fn write(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: u64,
        _offset: u64,
        _data: Vec<u8>,
        _flags: u32,
    ) -> ResultWrite {
        Err(libc::EROFS)
    }

    fn flush(&self, _req: RequestInfo, _path: &Path, _fh: u64, _lock_owner: u64) -> ResultEmpty {
        Ok(())
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
        open_files.remove(&fh).map(|_| ()).ok_or(libc::EBADF)
    }

    fn fsync(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        use std::os::unix::io::AsRawFd;

        let oflag = OFlag::from_bits_truncate(flags as i32);
        let mode = Mode::from_bits_truncate(flags);

        let dir = nix_err(Dir::open(&self.base_path(path), oflag, mode))?;
        let fh = dir.as_raw_fd() as u64;

        let mut open_dirs = self.open_dirs.lock().unwrap();
        open_dirs.insert(fh, dir);

        Ok((fh, 0))
    }

    fn readdir(&self, _req: RequestInfo, path: &Path, fh: u64) -> ResultReaddir {
        use std::os::unix::ffi::OsStrExt;

        let mut age_files = self.age_files.lock().unwrap();
        let mut open_dirs = self.open_dirs.lock().unwrap();
        let dir = open_dirs.get_mut(&fh).ok_or(libc::EBADF)?;

        dir.iter()
            .map(nix_err)
            .map(|res| {
                res.and_then(|entry| {
                    let kind = entry
                        .file_type()
                        .map(nix_type)
                        .ok_or(libc::EINVAL)
                        .or_else(|_| {
                            nix_err(
                                nix::sys::stat::fstat(fh as i32)
                                    .map(nix_stat)
                                    .map(|stat| stat.kind),
                            )
                        })?;
                    let name = Path::new(OsStr::from_bytes(entry.file_name().to_bytes()));

                    let name = match name.extension() {
                        Some(ext) if ext == "age" => {
                            let path = self.base_path(path).join(name);
                            match age_files.get(&path.with_extension("")) {
                                // We can decrypt this; remove the .age from the filename.
                                Some((_, Some(_))) => name.to_owned().with_extension("").into(),
                                // We can't decrypt this; leave the name as-is.
                                Some((_, None)) => name.into(),
                                // We haven't seen this .age file; test it!
                                None => {
                                    let (path, file) = check_file(path, &self.identities)
                                        .map_err(|e| e.raw_os_error().unwrap_or(0))?;
                                    let decrypted = file.is_some();

                                    // Remember whether we can decrypt this file!
                                    age_files.insert(path.with_extension(""), (path, file));

                                    if decrypted {
                                        // Remove the .age from the filename.
                                        name.to_owned().with_extension("").into()
                                    } else {
                                        name.into()
                                    }
                                }
                            }
                        }
                        _ => name.into(),
                    };

                    Ok(DirectoryEntry { name, kind })
                })
            })
            .collect()
    }

    fn releasedir(&self, _req: RequestInfo, _path: &Path, fh: u64, _flags: u32) -> ResultEmpty {
        let mut open_dirs = self.open_dirs.lock().unwrap();
        open_dirs.remove(&fh).map(|_| ()).ok_or(libc::EBADF)
    }

    fn fsyncdir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn statfs(&self, _req: RequestInfo, path: &Path) -> ResultStatfs {
        nix_err(nix::sys::statfs::statfs(&self.base_path(path))).map(nix_statfs)
    }

    fn setxattr(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _name: &OsStr,
        _value: &[u8],
        _flags: u32,
        _position: u32,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    /// Get a file extended attribute.
    ///
    /// * `path`: path to the file
    /// * `name`: attribute name.
    /// * `size`: the maximum number of bytes to read.
    ///
    /// If `size` is 0, return `Xattr::Size(n)` where `n` is the size of the attribute data.
    /// Otherwise, return `Xattr::Data(data)` with the requested data.
    fn getxattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr, _size: u32) -> ResultXattr {
        Err(libc::ENOSYS)
    }

    /// List extended attributes for a file.
    ///
    /// * `path`: path to the file.
    /// * `size`: maximum number of bytes to return.
    ///
    /// If `size` is 0, return `Xattr::Size(n)` where `n` is the size required for the list of
    /// attribute names.
    /// Otherwise, return `Xattr::Data(data)` where `data` is all the null-terminated attribute
    /// names.
    fn listxattr(&self, _req: RequestInfo, _path: &Path, _size: u32) -> ResultXattr {
        Err(libc::ENOSYS)
    }

    fn removexattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn access(&self, _req: RequestInfo, path: &Path, mask: u32) -> ResultEmpty {
        let amode = AccessFlags::from_bits_truncate(mask as i32);
        nix_err(nix::unistd::access(path, amode))
    }

    fn create(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _flags: u32,
    ) -> ResultCreate {
        Err(libc::EROFS)
    }

    #[cfg(target_os = "macos")]
    fn setvolname(&self, _req: RequestInfo, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }

    // exchange (macOS only, undocumented)

    /// macOS only: Query extended times (bkuptime and crtime).
    ///
    /// * `path`: path to the file to get the times for.
    ///
    /// Return an `XTimes` struct with the times, or other error code as appropriate.
    #[cfg(target_os = "macos")]
    fn getxtimes(&self, _req: RequestInfo, _path: &Path) -> ResultXTimes {
        Err(libc::ENOSYS)
    }
}
