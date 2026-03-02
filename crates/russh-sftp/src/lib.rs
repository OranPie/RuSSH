//! SFTP protocol model and bootstrap client/server helpers.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Component;
use std::path::{Path, PathBuf};

use russh_channel::Channel;
use russh_core::{RusshError, RusshErrorCategory};

/// Monotonic request id wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId(pub u32);

/// Minimal SFTP packet model used in early implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SftpPacket {
    Open {
        id: RequestId,
        path: String,
    },
    Read {
        id: RequestId,
        path: String,
    },
    Write {
        id: RequestId,
        path: String,
        data: Vec<u8>,
    },
    Close {
        id: RequestId,
        path: String,
    },
    Stat {
        id: RequestId,
        path: String,
    },
    ReadDir {
        id: RequestId,
        path: String,
    },
    Mkdir {
        id: RequestId,
        path: String,
    },
    Remove {
        id: RequestId,
        path: String,
    },
    Rename {
        id: RequestId,
        from: String,
        to: String,
    },
}

/// Filesystem metadata projection for SFTP responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpFileMetadata {
    pub size: u64,
    pub is_dir: bool,
    pub is_file: bool,
    pub readonly: bool,
}

/// Directory entry model used for list operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpDirEntry {
    pub name: String,
    pub metadata: SftpFileMetadata,
}

/// SFTP client façade bound to a transport channel.
#[derive(Clone, Debug)]
pub struct SftpClient {
    pub channel: Channel,
    pub root: PathBuf,
}

impl SftpClient {
    #[must_use]
    pub fn new(channel: Channel, root: impl Into<PathBuf>) -> Self {
        Self {
            channel,
            root: root.into(),
        }
    }

    pub fn read_file(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>, RusshError> {
        let full_path = self.resolve_path(relative)?;
        fs::read(&full_path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to read {:?}: {error}", full_path),
            )
        })
    }

    pub fn write_file(&self, relative: impl AsRef<Path>, data: &[u8]) -> Result<(), RusshError> {
        let full_path = self.resolve_path(relative)?;
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to create parent {:?}: {error}", parent),
                )
            })?;
        }

        fs::write(&full_path, data).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to write {:?}: {error}", full_path),
            )
        })
    }

    pub fn read_file_chunk(
        &self,
        relative: impl AsRef<Path>,
        offset: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, RusshError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }

        let full_path = self.resolve_path(relative)?;
        let mut file = fs::File::open(&full_path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to open {:?}: {error}", full_path),
            )
        })?;
        file.seek(SeekFrom::Start(offset)).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to seek {:?}: {error}", full_path),
            )
        })?;

        let mut buffer = vec![0u8; max_len];
        let read = file.read(&mut buffer).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to read {:?}: {error}", full_path),
            )
        })?;
        buffer.truncate(read);
        Ok(buffer)
    }

    pub fn write_file_chunk(
        &self,
        relative: impl AsRef<Path>,
        offset: u64,
        data: &[u8],
    ) -> Result<(), RusshError> {
        let full_path = self.resolve_path(relative)?;
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to create parent {:?}: {error}", parent),
                )
            })?;
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&full_path)
            .map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to open {:?}: {error}", full_path),
                )
            })?;
        file.seek(SeekFrom::Start(offset)).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to seek {:?}: {error}", full_path),
            )
        })?;
        file.write_all(data).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to write {:?}: {error}", full_path),
            )
        })
    }

    pub fn create_dir_all(&self, relative: impl AsRef<Path>) -> Result<(), RusshError> {
        let full_path = self.resolve_path(relative)?;
        fs::create_dir_all(&full_path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to create directory {:?}: {error}", full_path),
            )
        })
    }

    pub fn remove_file(&self, relative: impl AsRef<Path>) -> Result<(), RusshError> {
        let full_path = self.resolve_path(relative)?;
        fs::remove_file(&full_path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to remove file {:?}: {error}", full_path),
            )
        })
    }

    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), RusshError> {
        let source = self.resolve_path(from)?;
        let target = self.resolve_path(to)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to create parent {:?}: {error}", parent),
                )
            })?;
        }
        fs::rename(&source, &target).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to rename {:?} to {:?}: {error}", source, target),
            )
        })
    }

    pub fn stat(&self, relative: impl AsRef<Path>) -> Result<SftpFileMetadata, RusshError> {
        let full_path = self.resolve_path(relative)?;
        let metadata = fs::metadata(&full_path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to stat {:?}: {error}", full_path),
            )
        })?;
        Ok(metadata_to_sftp(&metadata))
    }

    pub fn list_dir(&self, relative: impl AsRef<Path>) -> Result<Vec<SftpDirEntry>, RusshError> {
        let full_path = self.resolve_path(relative)?;
        let mut entries = Vec::new();

        for entry in fs::read_dir(&full_path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to list {:?}: {error}", full_path),
            )
        })? {
            let entry = entry.map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to read directory entry in {:?}: {error}", full_path),
                )
            })?;
            let name = entry.file_name().to_string_lossy().to_string();
            let metadata = entry.metadata().map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to read metadata for {:?}: {error}", entry.path()),
                )
            })?;
            entries.push(SftpDirEntry {
                name,
                metadata: metadata_to_sftp(&metadata),
            });
        }

        entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    fn resolve_path(&self, relative: impl AsRef<Path>) -> Result<PathBuf, RusshError> {
        let relative = relative.as_ref();
        let mut sanitized = PathBuf::new();

        for component in relative.components() {
            match component {
                Component::Normal(part) => sanitized.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("path {:?} escapes SFTP root", relative),
                    ));
                }
            }
        }

        Ok(self.root.join(sanitized))
    }
}

/// SFTP server façade for subsystem attachment and packet handling.
#[derive(Clone, Debug)]
pub struct SftpServer {
    pub subsystem_name: String,
}

impl SftpServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subsystem_name: "sftp".to_string(),
        }
    }

    #[must_use]
    pub fn handle(&self, packet: &SftpPacket) -> &'static str {
        match packet {
            SftpPacket::Open { .. } => "open",
            SftpPacket::Read { .. } => "read",
            SftpPacket::Write { .. } => "write",
            SftpPacket::Close { .. } => "close",
            SftpPacket::Stat { .. } => "stat",
            SftpPacket::ReadDir { .. } => "readdir",
            SftpPacket::Mkdir { .. } => "mkdir",
            SftpPacket::Remove { .. } => "remove",
            SftpPacket::Rename { .. } => "rename",
        }
    }
}

impl Default for SftpServer {
    fn default() -> Self {
        Self::new()
    }
}

fn metadata_to_sftp(metadata: &fs::Metadata) -> SftpFileMetadata {
    SftpFileMetadata {
        size: metadata.len(),
        is_dir: metadata.is_dir(),
        is_file: metadata.is_file(),
        readonly: metadata.permissions().readonly(),
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    use russh_channel::{Channel, ChannelKind};

    use super::SftpClient;

    #[test]
    fn write_then_read_round_trip() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }

        let client = SftpClient::new(Channel::open(ChannelKind::Session), PathBuf::from(&root));
        client
            .write_file("nested/example.txt", b"hello")
            .expect("write should succeed");
        let data = client
            .read_file("nested/example.txt")
            .expect("read should succeed");

        assert_eq!(data, b"hello");

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn chunk_write_and_range_read_round_trip() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_chunk_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }

        let client = SftpClient::new(Channel::open(ChannelKind::Session), PathBuf::from(&root));
        client
            .write_file_chunk("data.bin", 0, b"hello")
            .expect("first chunk should succeed");
        client
            .write_file_chunk("data.bin", 5, b"-world")
            .expect("second chunk should succeed");

        let middle = client
            .read_file_chunk("data.bin", 3, 5)
            .expect("range read should succeed");
        let full = client
            .read_file("data.bin")
            .expect("full read should succeed");

        assert_eq!(middle, b"lo-wo");
        assert_eq!(full, b"hello-world");

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn list_dir_and_stat_report_metadata() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_list_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }

        let client = SftpClient::new(Channel::open(ChannelKind::Session), PathBuf::from(&root));
        client
            .write_file("nested/a.txt", b"a")
            .expect("write should succeed");
        client
            .write_file("nested/b.txt", b"bb")
            .expect("write should succeed");

        let stat = client.stat("nested/b.txt").expect("stat should succeed");
        let entries = client.list_dir("nested").expect("list should succeed");

        assert_eq!(stat.size, 2);
        assert!(stat.is_file);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[1].name, "b.txt");

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn traversal_path_is_rejected() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_traversal_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let client = SftpClient::new(Channel::open(ChannelKind::Session), PathBuf::from(&root));
        let error = client
            .write_file("../escape.txt", b"nope")
            .expect_err("traversal should be rejected");
        assert_eq!(error.category(), russh_core::RusshErrorCategory::Protocol);

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }
}
