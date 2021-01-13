use age::{armor::ArmoredReader, stream::StreamReader};
use fuse_mt::*;
use log::error;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use time::Timespec;

const ROOT_HANDLE: u64 = 0;
const FILE_HANDLE: u64 = 1;

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

pub struct AgeFileFs {
    inner: Mutex<StreamReader<ArmoredReader<BufReader<File>>>>,
    file_name: OsString,
    file_attr: FileAttr,
}

impl AgeFileFs {
    pub fn open(
        mut stream: StreamReader<ArmoredReader<BufReader<File>>>,
        metadata: Metadata,
        file_name: OsString,
    ) -> io::Result<Self> {
        let size = stream.seek(SeekFrom::End(0))?;

        let timespec = |t: SystemTime| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map(|t| Timespec::new(t.as_secs() as i64, t.subsec_nanos() as i32))
                .unwrap()
        };

        let mtime = metadata.modified().map(timespec)?;
        let ctime = metadata.created().map(timespec).unwrap_or(mtime);
        let atime = metadata.accessed().map(timespec).unwrap_or(mtime);

        Ok(AgeFileFs {
            inner: Mutex::new(stream),
            file_name,
            file_attr: FileAttr {
                size,
                blocks: 1,
                atime,
                mtime,
                ctime,
                crtime: ctime,
                kind: FileType::RegularFile,
                perm: 0o0444,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                rdev: 0,
                flags: 0,
            },
        })
    }
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

impl FilesystemMT for AgeFileFs {
    fn getattr(&self, _req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        if let Some(fh) = fh {
            match fh {
                ROOT_HANDLE => Ok((TTL, ROOT_ATTR)),
                FILE_HANDLE => Ok((TTL, self.file_attr)),
                _ => Err(libc::EBADF),
            }
        } else {
            let root = Path::new("/");
            if path == root {
                Ok((TTL, ROOT_ATTR))
            } else if path == root.join(&self.file_name) {
                Ok((TTL, self.file_attr))
            } else {
                Err(libc::ENOENT)
            }
        }
    }

    fn opendir(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> ResultOpen {
        Ok((ROOT_HANDLE, 0))
    }

    fn readdir(&self, _req: RequestInfo, _path: &Path, fh: u64) -> ResultReaddir {
        if fh == ROOT_HANDLE {
            Ok(vec![DirectoryEntry {
                name: self.file_name.clone(),
                kind: FileType::RegularFile,
            }])
        } else {
            Err(libc::EBADF)
        }
    }

    fn releasedir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _flags: u32) -> ResultEmpty {
        Ok(())
    }

    fn statfs(&self, _req: RequestInfo, _path: &Path) -> ResultStatfs {
        Ok(Statfs {
            blocks: 1,
            bfree: 0,
            bavail: 0,
            files: 1,
            ffree: 0,
            bsize: 64 * 1024,
            namelen: u32::max_value(),
            frsize: 64 * 1024,
        })
    }

    fn open(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> ResultOpen {
        Ok((FILE_HANDLE, 0))
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

        if fh == FILE_HANDLE {
            if offset > self.file_attr.size {
                return callback(Err(libc::EINVAL));
            }

            // Skip to offset
            if inner.seek(SeekFrom::Start(offset)).is_err() {
                return callback(Err(libc::EIO));
            }

            // Read bytes
            let to_read = usize::min(size as usize, (self.file_attr.size - offset) as usize);
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
        _fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> ResultEmpty {
        Ok(())
    }
}

pub struct AgeFileLink {
    link: PathBuf,
}

impl AgeFileLink {
    pub fn new(target: &Path, link: PathBuf) -> nix::Result<Self> {
        nix::unistd::symlinkat(target, None, &link)?;
        Ok(AgeFileLink { link })
    }
}

impl Drop for AgeFileLink {
    fn drop(&mut self) {
        if let Err(e) = nix::unistd::unlink(&self.link) {
            error!(
                "Failed to remove symbolic link {}: {}",
                self.link.to_string_lossy(),
                e
            );
        };
    }
}
