use std::io;

use fuse_mt::*;
use nix::{
    libc,
    sys::stat::{Mode, SFlag},
};
use time::Timespec;

pub(crate) fn nix_err<T>(res: nix::Result<T>) -> Result<T, libc::c_int> {
    // TODO: This clobbers nix-unknown errors to 0.
    res.map_err(|e| {
        e.as_errno()
            .map(io::Error::from)
            .and_then(|e| e.raw_os_error())
            .unwrap_or(0)
    })
}

pub(crate) fn nix_kind(kind: SFlag) -> FileType {
    match kind & SFlag::S_IFMT {
        SFlag::S_IFIFO => FileType::NamedPipe,
        SFlag::S_IFCHR => FileType::CharDevice,
        SFlag::S_IFDIR => FileType::Directory,
        SFlag::S_IFBLK => FileType::BlockDevice,
        SFlag::S_IFREG => FileType::RegularFile,
        SFlag::S_IFLNK => FileType::Symlink,
        SFlag::S_IFSOCK => FileType::Socket,
        _ => unreachable!(),
    }
}

pub(crate) fn nix_type(file_type: nix::dir::Type) -> FileType {
    use nix::dir::Type;
    match file_type {
        Type::Fifo => FileType::NamedPipe,
        Type::CharacterDevice => FileType::CharDevice,
        Type::Directory => FileType::Directory,
        Type::BlockDevice => FileType::BlockDevice,
        Type::File => FileType::RegularFile,
        Type::Symlink => FileType::Symlink,
        Type::Socket => FileType::Socket,
    }
}

pub(crate) fn nix_stat(stat: nix::sys::stat::FileStat) -> FileAttr {
    let kind = SFlag::from_bits_truncate(stat.st_mode);
    let perm = Mode::from_bits_truncate(stat.st_mode);

    FileAttr {
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: Timespec::new(stat.st_atime, stat.st_atime_nsec as i32),
        mtime: Timespec::new(stat.st_mtime, stat.st_mtime_nsec as i32),
        ctime: Timespec::new(stat.st_ctime, stat.st_ctime_nsec as i32),
        crtime: Timespec::new(0, 0),
        kind: nix_kind(kind),
        perm: perm.bits() as u16,
        nlink: stat.st_nlink as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u32,
        flags: 0,
    }
}

pub(crate) fn nix_statfs(statfs: nix::sys::statfs::Statfs) -> Statfs {
    Statfs {
        blocks: statfs.blocks(),
        bfree: 0,
        bavail: 0,
        files: statfs.files(),
        ffree: 0,
        bsize: statfs.optimal_transfer_size() as u32,
        namelen: statfs.maximum_name_length() as u32,
        frsize: statfs.optimal_transfer_size() as u32,
    }
}
