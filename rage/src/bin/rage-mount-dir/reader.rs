use std::fs::File;
use std::io;
use std::path::Path;

use age::stream::StreamReader;

use crate::wrapper::AgeFile;

pub(crate) enum OpenedFile {
    Normal(File),
    Age {
        reader: StreamReader<File>,
        handle: u64,
    },
}

impl OpenedFile {
    pub(crate) fn normal(path: &Path) -> io::Result<Self> {
        File::open(path).map(OpenedFile::Normal)
    }

    pub(crate) fn age(path: &Path, age_file: &AgeFile) -> io::Result<Self> {
        let file = File::open(path)?;

        use std::os::unix::io::AsRawFd;
        let handle = file.as_raw_fd() as u64;

        let decryptor = match age::Decryptor::new(file).unwrap() {
            age::Decryptor::Recipients(d) => d,
            _ => unreachable!(),
        };
        let reader = decryptor
            .decrypt(
                Some(&age_file.file_key)
                    .into_iter()
                    .map(|i| i as &dyn age::Identity),
            )
            .unwrap();

        Ok(OpenedFile::Age { reader, handle })
    }

    pub(crate) fn handle(&self) -> u64 {
        match self {
            OpenedFile::Normal(file) => {
                use std::os::unix::io::AsRawFd;
                file.as_raw_fd() as u64
            }
            OpenedFile::Age { handle, .. } => *handle,
        }
    }
}

impl io::Read for OpenedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            OpenedFile::Normal(file) => file.read(buf),
            OpenedFile::Age { reader, .. } => reader.read(buf),
        }
    }
}

impl io::Seek for OpenedFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        match self {
            OpenedFile::Normal(file) => file.seek(pos),
            OpenedFile::Age { reader, .. } => reader.seek(pos),
        }
    }
}
