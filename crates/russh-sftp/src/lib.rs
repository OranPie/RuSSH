//! SFTP v3 protocol codec and server for RuSSH (draft-ietf-secsh-filexfer-02).
//!
//! ## Wire codec
//!
//! [`SftpWirePacket`] encodes and decodes all SFTP v3 wire packets:
//! - **Client→Server**: INIT, OPEN, CLOSE, READ, WRITE, LSTAT, FSTAT,
//!   SETSTAT, FSETSTAT, OPENDIR, READDIR, REMOVE, MKDIR, RMDIR, REALPATH, STAT, RENAME,
//!   READLINK, SYMLINK
//! - **Server→Client**: VERSION, STATUS, HANDLE, DATA, NAME, ATTRS
//!
//! Packet format: `uint32 length || byte type || body` with all integers
//! big-endian and strings length-prefixed per RFC 4251.
//!
//! [`FileAttrs`] carries file metadata (size, uid/gid, permissions, timestamps)
//! with flags controlling which fields are present.
//!
//! [`SftpFramer`] buffers a byte stream and yields complete [`SftpWirePacket`]
//! frames as they arrive.
//!
//! ## Filesystem server
//!
//! [`SftpFileServer`] processes SFTP v3 request packets against a chrooted
//! local filesystem, returning the appropriate response packet for each request.
//! Handles file handles (read/write), directory handles (readdir), and all
//! standard filesystem operations.
//!
//! ## High-level client (existing)
//!
//! [`SftpClient`] provides a high-level API operating on a sandboxed local
//! directory, suitable for testing and integration scenarios.

use std::collections::HashMap;
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

// ---------------------------------------------------------------------------
// SFTP v3 wire codec
// ---------------------------------------------------------------------------

/// SFTP v3 packet type constants (draft-ietf-secsh-filexfer-02)
pub mod sftp_type {
    pub const INIT: u8 = 1;
    pub const VERSION: u8 = 2;
    pub const OPEN: u8 = 3;
    pub const CLOSE: u8 = 4;
    pub const READ: u8 = 5;
    pub const WRITE: u8 = 6;
    pub const LSTAT: u8 = 7;
    pub const FSTAT: u8 = 8;
    pub const SETSTAT: u8 = 9;
    pub const FSETSTAT: u8 = 10;
    pub const OPENDIR: u8 = 11;
    pub const READDIR: u8 = 12;
    pub const REMOVE: u8 = 13;
    pub const MKDIR: u8 = 14;
    pub const RMDIR: u8 = 15;
    pub const REALPATH: u8 = 16;
    pub const STAT: u8 = 17;
    pub const RENAME: u8 = 18;
    pub const SSH_FXP_READLINK: u8 = 19;
    pub const SSH_FXP_SYMLINK: u8 = 20;
    pub const STATUS: u8 = 101;
    pub const EXTENDED: u8 = 200;
    pub const EXTENDED_REPLY: u8 = 201;
    pub const HANDLE: u8 = 102;
    pub const DATA: u8 = 103;
    pub const NAME: u8 = 104;
    pub const ATTRS: u8 = 105;
}

/// SFTP v3 ATTRS flags
pub mod attr_flags {
    pub const SIZE: u32 = 0x00000001;
    pub const UIDGID: u32 = 0x00000002;
    pub const PERMISSIONS: u32 = 0x00000004;
    pub const ACMODTIME: u32 = 0x00000008;
}

/// SFTP open flags (SSH_FXF_*)
pub mod open_flags {
    pub const READ: u32 = 0x00000001;
    pub const WRITE: u32 = 0x00000002;
    pub const APPEND: u32 = 0x00000004;
    pub const CREAT: u32 = 0x00000008;
    pub const TRUNC: u32 = 0x00000010;
    pub const EXCL: u32 = 0x00000020;
}

// --- Private wire-encoding helpers ---

fn sftp_read_u32(data: &[u8], off: &mut usize) -> Result<u32, RusshError> {
    if *off + 4 > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "unexpected end of SFTP packet",
        ));
    }
    let v = u32::from_be_bytes([data[*off], data[*off + 1], data[*off + 2], data[*off + 3]]);
    *off += 4;
    Ok(v)
}

fn sftp_read_u64(data: &[u8], off: &mut usize) -> Result<u64, RusshError> {
    if *off + 8 > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "unexpected end of SFTP packet",
        ));
    }
    let v = u64::from_be_bytes([
        data[*off],
        data[*off + 1],
        data[*off + 2],
        data[*off + 3],
        data[*off + 4],
        data[*off + 5],
        data[*off + 6],
        data[*off + 7],
    ]);
    *off += 8;
    Ok(v)
}

fn sftp_read_string(data: &[u8], off: &mut usize) -> Result<Vec<u8>, RusshError> {
    let len = sftp_read_u32(data, off)? as usize;
    if *off + len > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "unexpected end of SFTP string",
        ));
    }
    let s = data[*off..*off + len].to_vec();
    *off += len;
    Ok(s)
}

fn sftp_read_utf8(data: &[u8], off: &mut usize) -> Result<String, RusshError> {
    let bytes = sftp_read_string(data, off)?;
    String::from_utf8(bytes).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "SFTP string is not valid UTF-8",
        )
    })
}

fn sftp_write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn sftp_write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn sftp_write_string(out: &mut Vec<u8>, s: &[u8]) {
    sftp_write_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

// --- Public types ---

/// SSH_FX_* status codes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SftpStatus {
    Ok,
    Eof,
    NoSuchFile,
    PermissionDenied,
    Failure,
    BadMessage,
    Unsupported,
}

impl SftpStatus {
    pub fn to_code(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Eof => 1,
            Self::NoSuchFile => 2,
            Self::PermissionDenied => 3,
            Self::Failure => 4,
            Self::BadMessage => 5,
            Self::Unsupported => 8,
        }
    }

    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Eof,
            2 => Self::NoSuchFile,
            3 => Self::PermissionDenied,
            4 => Self::Failure,
            5 => Self::BadMessage,
            _ => Self::Failure,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Eof => "end of file",
            Self::NoSuchFile => "no such file",
            Self::PermissionDenied => "permission denied",
            Self::Failure => "failure",
            Self::BadMessage => "bad message",
            Self::Unsupported => "unsupported",
        }
    }
}

/// SFTP file attributes
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileAttrs {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl FileAttrs {
    pub fn encode(&self) -> Vec<u8> {
        let mut flags: u32 = 0;
        if self.size.is_some() {
            flags |= attr_flags::SIZE;
        }
        if self.uid.is_some() && self.gid.is_some() {
            flags |= attr_flags::UIDGID;
        }
        if self.permissions.is_some() {
            flags |= attr_flags::PERMISSIONS;
        }
        if self.atime.is_some() && self.mtime.is_some() {
            flags |= attr_flags::ACMODTIME;
        }
        let mut out = Vec::new();
        sftp_write_u32(&mut out, flags);
        if let Some(sz) = self.size {
            sftp_write_u64(&mut out, sz);
        }
        if let (Some(uid), Some(gid)) = (self.uid, self.gid) {
            sftp_write_u32(&mut out, uid);
            sftp_write_u32(&mut out, gid);
        }
        if let Some(perm) = self.permissions {
            sftp_write_u32(&mut out, perm);
        }
        if let (Some(atime), Some(mtime)) = (self.atime, self.mtime) {
            sftp_write_u32(&mut out, atime);
            sftp_write_u32(&mut out, mtime);
        }
        out
    }

    pub fn decode(data: &[u8], offset: &mut usize) -> Result<Self, RusshError> {
        let flags = sftp_read_u32(data, offset)?;
        let size = if flags & attr_flags::SIZE != 0 {
            Some(sftp_read_u64(data, offset)?)
        } else {
            None
        };
        let (uid, gid) = if flags & attr_flags::UIDGID != 0 {
            (
                Some(sftp_read_u32(data, offset)?),
                Some(sftp_read_u32(data, offset)?),
            )
        } else {
            (None, None)
        };
        let permissions = if flags & attr_flags::PERMISSIONS != 0 {
            Some(sftp_read_u32(data, offset)?)
        } else {
            None
        };
        let (atime, mtime) = if flags & attr_flags::ACMODTIME != 0 {
            (
                Some(sftp_read_u32(data, offset)?),
                Some(sftp_read_u32(data, offset)?),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            size,
            uid,
            gid,
            permissions,
            atime,
            mtime,
        })
    }

    pub fn from_fs_metadata(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                size: Some(meta.len()),
                uid: Some(meta.uid()),
                gid: Some(meta.gid()),
                permissions: Some(meta.mode()),
                atime: Some(meta.atime() as u32),
                mtime: Some(meta.mtime() as u32),
            }
        }
        #[cfg(not(unix))]
        Self {
            size: Some(meta.len()),
            ..Default::default()
        }
    }
}

/// A single entry in an SFTP SSH_FXP_NAME response
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpNameEntry {
    pub filename: String,
    pub longname: String,
    pub attrs: FileAttrs,
}

/// A single SFTP v3 wire packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SftpWirePacket {
    // Client → Server
    Init {
        version: u32,
    },
    Open {
        id: u32,
        filename: String,
        pflags: u32,
        attrs: FileAttrs,
    },
    Close {
        id: u32,
        handle: Vec<u8>,
    },
    Read {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        len: u32,
    },
    Write {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        data: Vec<u8>,
    },
    Lstat {
        id: u32,
        path: String,
    },
    Fstat {
        id: u32,
        handle: Vec<u8>,
    },
    Setstat {
        id: u32,
        path: String,
        attrs: FileAttrs,
    },
    Fsetstat {
        id: u32,
        handle: Vec<u8>,
        attrs: FileAttrs,
    },
    Opendir {
        id: u32,
        path: String,
    },
    Readdir {
        id: u32,
        handle: Vec<u8>,
    },
    Remove {
        id: u32,
        filename: String,
    },
    Mkdir {
        id: u32,
        path: String,
        attrs: FileAttrs,
    },
    Rmdir {
        id: u32,
        path: String,
    },
    Realpath {
        id: u32,
        path: String,
    },
    Stat {
        id: u32,
        path: String,
    },
    Rename {
        id: u32,
        oldpath: String,
        newpath: String,
    },
    Readlink {
        id: u32,
        path: String,
    },
    /// OpenSSH reverses the argument order: target_path comes first on the wire.
    Symlink {
        id: u32,
        target_path: String,
        link_path: String,
    },
    /// SSH_FXP_EXTENDED (type 200) — carries an extension request.
    Extended {
        id: u32,
        extension_name: String,
        data: Vec<u8>,
    },
    // Server → Client
    Version {
        version: u32,
        extensions: Vec<(String, String)>,
    },
    Status {
        id: u32,
        status: SftpStatus,
        message: String,
    },
    Handle {
        id: u32,
        handle: Vec<u8>,
    },
    Data {
        id: u32,
        data: Vec<u8>,
    },
    Name {
        id: u32,
        entries: Vec<SftpNameEntry>,
    },
    AttrsReply {
        id: u32,
        attrs: FileAttrs,
    },
    /// SSH_FXP_EXTENDED_REPLY (type 201) — response to an extension request.
    ExtendedReply {
        id: u32,
        data: Vec<u8>,
    },
}

impl SftpWirePacket {
    /// Encode to `uint32 length || byte type || body`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Self::Init { version } => {
                body.push(sftp_type::INIT);
                sftp_write_u32(&mut body, *version);
            }
            Self::Version {
                version,
                extensions,
            } => {
                body.push(sftp_type::VERSION);
                sftp_write_u32(&mut body, *version);
                for (name, value) in extensions {
                    sftp_write_string(&mut body, name.as_bytes());
                    sftp_write_string(&mut body, value.as_bytes());
                }
            }
            Self::Open {
                id,
                filename,
                pflags,
                attrs,
            } => {
                body.push(sftp_type::OPEN);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, filename.as_bytes());
                sftp_write_u32(&mut body, *pflags);
                body.extend_from_slice(&attrs.encode());
            }
            Self::Close { id, handle } => {
                body.push(sftp_type::CLOSE);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
            }
            Self::Read {
                id,
                handle,
                offset,
                len,
            } => {
                body.push(sftp_type::READ);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
                sftp_write_u64(&mut body, *offset);
                sftp_write_u32(&mut body, *len);
            }
            Self::Write {
                id,
                handle,
                offset,
                data,
            } => {
                body.push(sftp_type::WRITE);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
                sftp_write_u64(&mut body, *offset);
                sftp_write_string(&mut body, data);
            }
            Self::Lstat { id, path } => {
                body.push(sftp_type::LSTAT);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
            }
            Self::Fstat { id, handle } => {
                body.push(sftp_type::FSTAT);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
            }
            Self::Setstat { id, path, attrs } => {
                body.push(sftp_type::SETSTAT);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
                body.extend_from_slice(&attrs.encode());
            }
            Self::Fsetstat { id, handle, attrs } => {
                body.push(sftp_type::FSETSTAT);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
                body.extend_from_slice(&attrs.encode());
            }
            Self::Opendir { id, path } => {
                body.push(sftp_type::OPENDIR);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
            }
            Self::Readdir { id, handle } => {
                body.push(sftp_type::READDIR);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
            }
            Self::Remove { id, filename } => {
                body.push(sftp_type::REMOVE);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, filename.as_bytes());
            }
            Self::Mkdir { id, path, attrs } => {
                body.push(sftp_type::MKDIR);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
                body.extend_from_slice(&attrs.encode());
            }
            Self::Rmdir { id, path } => {
                body.push(sftp_type::RMDIR);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
            }
            Self::Realpath { id, path } => {
                body.push(sftp_type::REALPATH);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
            }
            Self::Stat { id, path } => {
                body.push(sftp_type::STAT);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
            }
            Self::Rename {
                id,
                oldpath,
                newpath,
            } => {
                body.push(sftp_type::RENAME);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, oldpath.as_bytes());
                sftp_write_string(&mut body, newpath.as_bytes());
            }
            Self::Readlink { id, path } => {
                body.push(sftp_type::SSH_FXP_READLINK);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, path.as_bytes());
            }
            Self::Symlink {
                id,
                target_path,
                link_path,
            } => {
                // OpenSSH order: target_path first, then link_path
                body.push(sftp_type::SSH_FXP_SYMLINK);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, target_path.as_bytes());
                sftp_write_string(&mut body, link_path.as_bytes());
            }
            Self::Status {
                id,
                status,
                message,
            } => {
                body.push(sftp_type::STATUS);
                sftp_write_u32(&mut body, *id);
                sftp_write_u32(&mut body, status.to_code());
                sftp_write_string(&mut body, message.as_bytes());
                sftp_write_string(&mut body, b"en");
            }
            Self::Handle { id, handle } => {
                body.push(sftp_type::HANDLE);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, handle);
            }
            Self::Data { id, data } => {
                body.push(sftp_type::DATA);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, data);
            }
            Self::Name { id, entries } => {
                body.push(sftp_type::NAME);
                sftp_write_u32(&mut body, *id);
                sftp_write_u32(&mut body, entries.len() as u32);
                for entry in entries {
                    sftp_write_string(&mut body, entry.filename.as_bytes());
                    sftp_write_string(&mut body, entry.longname.as_bytes());
                    body.extend_from_slice(&entry.attrs.encode());
                }
            }
            Self::AttrsReply { id, attrs } => {
                body.push(sftp_type::ATTRS);
                sftp_write_u32(&mut body, *id);
                body.extend_from_slice(&attrs.encode());
            }
            Self::Extended {
                id,
                extension_name,
                data,
            } => {
                body.push(sftp_type::EXTENDED);
                sftp_write_u32(&mut body, *id);
                sftp_write_string(&mut body, extension_name.as_bytes());
                body.extend_from_slice(data);
            }
            Self::ExtendedReply { id, data } => {
                body.push(sftp_type::EXTENDED_REPLY);
                sftp_write_u32(&mut body, *id);
                body.extend_from_slice(data);
            }
        }
        let mut out = Vec::new();
        sftp_write_u32(&mut out, body.len() as u32);
        out.extend_from_slice(&body);
        out
    }

    /// Decode from `uint32 length || byte type || body` (including the 4-byte length prefix).
    pub fn decode(data: &[u8]) -> Result<Self, RusshError> {
        if data.len() < 5 {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "SFTP packet too short",
            ));
        }
        let mut off = 0usize;
        let len = sftp_read_u32(data, &mut off)? as usize;
        if len == 0 || data.len() < 4 + len {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "SFTP packet truncated",
            ));
        }
        let ptype = data[off];
        off += 1;
        let end = 4 + len;

        let packet = match ptype {
            sftp_type::INIT => {
                let version = sftp_read_u32(data, &mut off)?;
                Self::Init { version }
            }
            sftp_type::VERSION => {
                let version = sftp_read_u32(data, &mut off)?;
                let mut extensions = Vec::new();
                while off < end {
                    let name = sftp_read_utf8(data, &mut off)?;
                    let value = sftp_read_utf8(data, &mut off)?;
                    extensions.push((name, value));
                }
                Self::Version {
                    version,
                    extensions,
                }
            }
            sftp_type::OPEN => {
                let id = sftp_read_u32(data, &mut off)?;
                let filename = sftp_read_utf8(data, &mut off)?;
                let pflags = sftp_read_u32(data, &mut off)?;
                let attrs = FileAttrs::decode(data, &mut off)?;
                Self::Open {
                    id,
                    filename,
                    pflags,
                    attrs,
                }
            }
            sftp_type::CLOSE => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                Self::Close { id, handle }
            }
            sftp_type::READ => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                let offset = sftp_read_u64(data, &mut off)?;
                let rlen = sftp_read_u32(data, &mut off)?;
                Self::Read {
                    id,
                    handle,
                    offset,
                    len: rlen,
                }
            }
            sftp_type::WRITE => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                let offset = sftp_read_u64(data, &mut off)?;
                let wdata = sftp_read_string(data, &mut off)?;
                Self::Write {
                    id,
                    handle,
                    offset,
                    data: wdata,
                }
            }
            sftp_type::LSTAT => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                Self::Lstat { id, path }
            }
            sftp_type::FSTAT => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                Self::Fstat { id, handle }
            }
            sftp_type::SETSTAT => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                let attrs = FileAttrs::decode(data, &mut off)?;
                Self::Setstat { id, path, attrs }
            }
            sftp_type::FSETSTAT => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                let attrs = FileAttrs::decode(data, &mut off)?;
                Self::Fsetstat { id, handle, attrs }
            }
            sftp_type::OPENDIR => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                Self::Opendir { id, path }
            }
            sftp_type::READDIR => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                Self::Readdir { id, handle }
            }
            sftp_type::REMOVE => {
                let id = sftp_read_u32(data, &mut off)?;
                let filename = sftp_read_utf8(data, &mut off)?;
                Self::Remove { id, filename }
            }
            sftp_type::MKDIR => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                let attrs = FileAttrs::decode(data, &mut off)?;
                Self::Mkdir { id, path, attrs }
            }
            sftp_type::RMDIR => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                Self::Rmdir { id, path }
            }
            sftp_type::REALPATH => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                Self::Realpath { id, path }
            }
            sftp_type::STAT => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                Self::Stat { id, path }
            }
            sftp_type::RENAME => {
                let id = sftp_read_u32(data, &mut off)?;
                let oldpath = sftp_read_utf8(data, &mut off)?;
                let newpath = sftp_read_utf8(data, &mut off)?;
                Self::Rename {
                    id,
                    oldpath,
                    newpath,
                }
            }
            sftp_type::SSH_FXP_READLINK => {
                let id = sftp_read_u32(data, &mut off)?;
                let path = sftp_read_utf8(data, &mut off)?;
                Self::Readlink { id, path }
            }
            sftp_type::SSH_FXP_SYMLINK => {
                // OpenSSH order: target_path first, then link_path
                let id = sftp_read_u32(data, &mut off)?;
                let target_path = sftp_read_utf8(data, &mut off)?;
                let link_path = sftp_read_utf8(data, &mut off)?;
                Self::Symlink {
                    id,
                    target_path,
                    link_path,
                }
            }
            sftp_type::STATUS => {
                let id = sftp_read_u32(data, &mut off)?;
                let code = sftp_read_u32(data, &mut off)?;
                let msg_bytes = sftp_read_string(data, &mut off)?;
                // skip optional language tag
                if off < end {
                    let _lang = sftp_read_string(data, &mut off);
                }
                let message = String::from_utf8(msg_bytes).unwrap_or_default();
                Self::Status {
                    id,
                    status: SftpStatus::from_code(code),
                    message,
                }
            }
            sftp_type::HANDLE => {
                let id = sftp_read_u32(data, &mut off)?;
                let handle = sftp_read_string(data, &mut off)?;
                Self::Handle { id, handle }
            }
            sftp_type::DATA => {
                let id = sftp_read_u32(data, &mut off)?;
                let pdata = sftp_read_string(data, &mut off)?;
                Self::Data { id, data: pdata }
            }
            sftp_type::NAME => {
                let id = sftp_read_u32(data, &mut off)?;
                let count = sftp_read_u32(data, &mut off)?;
                let mut entries = Vec::new();
                for _ in 0..count {
                    let filename = sftp_read_utf8(data, &mut off)?;
                    let longname = sftp_read_utf8(data, &mut off)?;
                    let attrs = FileAttrs::decode(data, &mut off)?;
                    entries.push(SftpNameEntry {
                        filename,
                        longname,
                        attrs,
                    });
                }
                Self::Name { id, entries }
            }
            sftp_type::ATTRS => {
                let id = sftp_read_u32(data, &mut off)?;
                let attrs = FileAttrs::decode(data, &mut off)?;
                Self::AttrsReply { id, attrs }
            }
            sftp_type::EXTENDED => {
                let id = sftp_read_u32(data, &mut off)?;
                let extension_name = sftp_read_utf8(data, &mut off)?;
                let ext_data = data[off..end].to_vec();
                Self::Extended {
                    id,
                    extension_name,
                    data: ext_data,
                }
            }
            sftp_type::EXTENDED_REPLY => {
                let id = sftp_read_u32(data, &mut off)?;
                let reply_data = data[off..end].to_vec();
                Self::ExtendedReply {
                    id,
                    data: reply_data,
                }
            }
            _ => {
                return Err(RusshError::new(
                    RusshErrorCategory::Protocol,
                    format!("unknown SFTP packet type {ptype}"),
                ));
            }
        };
        Ok(packet)
    }
}

// ---------------------------------------------------------------------------
// SftpFileServer — processes SFTP v3 packets against the local filesystem
// ---------------------------------------------------------------------------

enum SftpHandle {
    File(fs::File, PathBuf),
    Dir(ReadDirState),
}

struct ReadDirState {
    _path: PathBuf,
    entries: Vec<SftpNameEntry>,
    consumed: bool,
}

/// SFTP v3 server that handles requests against a chrooted local filesystem.
pub struct SftpFileServer {
    root: PathBuf,
    handles: HashMap<Vec<u8>, SftpHandle>,
    next_handle: u32,
}

impl SftpFileServer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            handles: HashMap::new(),
            next_handle: 0,
        }
    }

    fn canonical_root(&self) -> Result<PathBuf, RusshError> {
        fs::canonicalize(&self.root).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to canonicalize SFTP root {:?}: {error}", self.root),
            )
        })
    }

    fn alloc_handle(&mut self) -> Vec<u8> {
        let n = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        n.to_be_bytes().to_vec()
    }

    fn resolve_path(&self, path: &str) -> Result<PathBuf, RusshError> {
        let p = Path::new(path);
        let mut sanitized = PathBuf::new();
        for component in p.components() {
            match component {
                Component::Normal(part) => sanitized.push(part),
                Component::CurDir => {}
                Component::RootDir => {} // treat as chroot — root is already self.root
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("path {:?} escapes SFTP root", path),
                    ));
                }
            }
        }
        Ok(self.root.join(sanitized))
    }

    fn validate_within_root(
        &self,
        path: &Path,
        allow_missing_leaf: bool,
    ) -> Result<(), RusshError> {
        let canonical_root = self.canonical_root()?;
        let mut current = if allow_missing_leaf && !path.exists() {
            path.parent().unwrap_or(path)
        } else {
            path
        };

        loop {
            match fs::canonicalize(current) {
                Ok(resolved) => {
                    if resolved.starts_with(&canonical_root) {
                        return Ok(());
                    }
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("path {:?} escapes SFTP root", path),
                    ));
                }
                Err(_) if allow_missing_leaf => {
                    if let Some(parent) = current.parent() {
                        current = parent;
                        continue;
                    }
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("path {:?} escapes SFTP root", path),
                    ));
                }
                Err(error) => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Io,
                        format!("failed to resolve SFTP path {:?}: {error}", path),
                    ));
                }
            }
        }
    }

    fn resolve_path_checked(
        &self,
        path: &str,
        allow_missing_leaf: bool,
    ) -> Result<PathBuf, RusshError> {
        let full_path = self.resolve_path(path)?;
        self.validate_within_root(&full_path, allow_missing_leaf)?;
        Ok(full_path)
    }

    fn display_path(&self, path: &Path) -> Result<String, RusshError> {
        let canonical_root = self.canonical_root()?;
        let resolved = fs::canonicalize(path).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to canonicalize SFTP path {:?}: {error}", path),
            )
        })?;
        if !resolved.starts_with(&canonical_root) {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!("path {:?} escapes SFTP root", path),
            ));
        }
        let relative = resolved.strip_prefix(&canonical_root).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                format!("path {:?} escapes SFTP root", path),
            )
        })?;
        if relative.as_os_str().is_empty() {
            Ok("/".to_string())
        } else {
            Ok(format!("/{}", relative.display()))
        }
    }

    fn io_status(e: &std::io::Error) -> SftpStatus {
        match e.kind() {
            std::io::ErrorKind::NotFound => SftpStatus::NoSuchFile,
            std::io::ErrorKind::PermissionDenied => SftpStatus::PermissionDenied,
            _ => SftpStatus::Failure,
        }
    }

    fn status_ok(id: u32) -> SftpWirePacket {
        SftpWirePacket::Status {
            id,
            status: SftpStatus::Ok,
            message: SftpStatus::Ok.message().to_string(),
        }
    }

    fn status_err(id: u32, e: &std::io::Error) -> SftpWirePacket {
        SftpWirePacket::Status {
            id,
            status: Self::io_status(e),
            message: e.to_string(),
        }
    }

    fn handle_posix_rename(&mut self, id: u32, data: &[u8]) -> Result<SftpWirePacket, RusshError> {
        let mut off = 0;
        let old_path = sftp_read_utf8(data, &mut off)?;
        let new_path = sftp_read_utf8(data, &mut off)?;
        let old = match self.resolve_path_checked(&old_path, false) {
            Err(_) => {
                return Ok(SftpWirePacket::Status {
                    id,
                    status: SftpStatus::PermissionDenied,
                    message: "path escapes root".to_string(),
                });
            }
            Ok(p) => p,
        };
        let new = match self.resolve_path_checked(&new_path, true) {
            Err(_) => {
                return Ok(SftpWirePacket::Status {
                    id,
                    status: SftpStatus::PermissionDenied,
                    message: "path escapes root".to_string(),
                });
            }
            Ok(p) => p,
        };
        match fs::rename(&old, &new) {
            Ok(_) => Ok(Self::status_ok(id)),
            Err(e) => Ok(Self::status_err(id, &e)),
        }
    }

    fn handle_statvfs(&self, id: u32, data: &[u8]) -> Result<SftpWirePacket, RusshError> {
        let mut off = 0;
        let path = sftp_read_utf8(data, &mut off)?;
        // Validate path is within root
        let _full_path = match self.resolve_path_checked(&path, false) {
            Err(_) => {
                return Ok(SftpWirePacket::Status {
                    id,
                    status: SftpStatus::PermissionDenied,
                    message: "path escapes root".to_string(),
                });
            }
            Ok(p) => p,
        };
        // Return hardcoded defaults; calling libc statvfs would require unsafe code.
        // The OpenSSH statvfs@openssh.com response is 11 uint64 values.
        let mut reply_data = Vec::new();
        sftp_write_u64(&mut reply_data, 4096); // f_bsize
        sftp_write_u64(&mut reply_data, 4096); // f_frsize
        sftp_write_u64(&mut reply_data, 1_000_000); // f_blocks
        sftp_write_u64(&mut reply_data, 500_000); // f_bfree
        sftp_write_u64(&mut reply_data, 500_000); // f_bavail
        sftp_write_u64(&mut reply_data, 1_000_000); // f_files
        sftp_write_u64(&mut reply_data, 500_000); // f_ffree
        sftp_write_u64(&mut reply_data, 500_000); // f_favail
        sftp_write_u64(&mut reply_data, 0); // f_fsid
        sftp_write_u64(&mut reply_data, 0); // f_flag
        sftp_write_u64(&mut reply_data, 255); // f_namemax
        Ok(SftpWirePacket::ExtendedReply {
            id,
            data: reply_data,
        })
    }

    fn handle_hardlink(&mut self, id: u32, data: &[u8]) -> Result<SftpWirePacket, RusshError> {
        let mut off = 0;
        let old_path = sftp_read_utf8(data, &mut off)?;
        let new_path = sftp_read_utf8(data, &mut off)?;
        let old = match self.resolve_path_checked(&old_path, false) {
            Err(_) => {
                return Ok(SftpWirePacket::Status {
                    id,
                    status: SftpStatus::PermissionDenied,
                    message: "path escapes root".to_string(),
                });
            }
            Ok(p) => p,
        };
        let new = match self.resolve_path_checked(&new_path, true) {
            Err(_) => {
                return Ok(SftpWirePacket::Status {
                    id,
                    status: SftpStatus::PermissionDenied,
                    message: "path escapes root".to_string(),
                });
            }
            Ok(p) => p,
        };
        match fs::hard_link(&old, &new) {
            Ok(_) => Ok(Self::status_ok(id)),
            Err(e) => Ok(Self::status_err(id, &e)),
        }
    }

    fn handle_fsync(&self, id: u32, data: &[u8]) -> Result<SftpWirePacket, RusshError> {
        let mut off = 0;
        let handle = sftp_read_string(data, &mut off)?;
        match self.handles.get(&handle) {
            Some(SftpHandle::File(file, _)) => match file.sync_all() {
                Ok(_) => Ok(Self::status_ok(id)),
                Err(e) => Ok(Self::status_err(id, &e)),
            },
            _ => Ok(SftpWirePacket::Status {
                id,
                status: SftpStatus::Failure,
                message: "invalid handle".to_string(),
            }),
        }
    }

    /// Apply file attributes to a filesystem path.
    fn apply_attrs(path: &Path, attrs: &FileAttrs) -> std::io::Result<()> {
        if let Some(size) = attrs.size {
            let file = fs::OpenOptions::new().write(true).open(path)?;
            file.set_len(size)?;
        }
        #[cfg(unix)]
        if let Some(perm) = attrs.permissions {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(perm))?;
        }
        if let (Some(atime), Some(mtime)) = (attrs.atime, attrs.mtime) {
            filetime::set_file_times(
                path,
                filetime::FileTime::from_unix_time(i64::from(atime), 0),
                filetime::FileTime::from_unix_time(i64::from(mtime), 0),
            )?;
        }
        Ok(())
    }

    /// Process a request packet and return the response packet.
    pub fn process(&mut self, request: &SftpWirePacket) -> Result<SftpWirePacket, RusshError> {
        match request {
            SftpWirePacket::Init { .. } => Ok(SftpWirePacket::Version {
                version: 3,
                extensions: vec![
                    ("posix-rename@openssh.com".to_string(), "1".to_string()),
                    ("statvfs@openssh.com".to_string(), "2".to_string()),
                    ("hardlink@openssh.com".to_string(), "1".to_string()),
                    ("fsync@openssh.com".to_string(), "1".to_string()),
                ],
            }),

            SftpWirePacket::Open {
                id,
                filename,
                pflags,
                ..
            } => {
                let id = *id;
                let full_path = match self.resolve_path_checked(filename, true) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                let read = pflags & open_flags::READ != 0;
                let write = pflags & open_flags::WRITE != 0;
                let append = pflags & open_flags::APPEND != 0;
                let creat = pflags & open_flags::CREAT != 0;
                let trunc = pflags & open_flags::TRUNC != 0;
                let excl = pflags & open_flags::EXCL != 0;
                if creat {
                    if let Some(parent) = full_path.parent() {
                        let _mkdir = fs::create_dir_all(parent);
                    }
                }
                let result = fs::OpenOptions::new()
                    .read(read)
                    .write(write || append)
                    .append(append)
                    .create(creat && !excl)
                    .create_new(excl)
                    .truncate(trunc)
                    .open(&full_path);
                match result {
                    Ok(file) => {
                        let handle = self.alloc_handle();
                        self.handles
                            .insert(handle.clone(), SftpHandle::File(file, full_path));
                        Ok(SftpWirePacket::Handle { id, handle })
                    }
                    Err(e) => Ok(Self::status_err(id, &e)),
                }
            }

            SftpWirePacket::Close { id, handle } => {
                let id = *id;
                self.handles.remove(handle);
                Ok(Self::status_ok(id))
            }

            SftpWirePacket::Read {
                id,
                handle,
                offset,
                len,
            } => {
                let id = *id;
                let offset = *offset;
                let max = *len as usize;
                match self.handles.get_mut(handle) {
                    Some(SftpHandle::File(file, _)) => match file.seek(SeekFrom::Start(offset)) {
                        Err(e) => Ok(Self::status_err(id, &e)),
                        Ok(_) => {
                            let mut buf = vec![0u8; max];
                            match file.read(&mut buf) {
                                Err(e) => Ok(Self::status_err(id, &e)),
                                Ok(0) => Ok(SftpWirePacket::Status {
                                    id,
                                    status: SftpStatus::Eof,
                                    message: SftpStatus::Eof.message().to_string(),
                                }),
                                Ok(n) => {
                                    buf.truncate(n);
                                    Ok(SftpWirePacket::Data { id, data: buf })
                                }
                            }
                        }
                    },
                    _ => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::Failure,
                        message: "invalid handle".to_string(),
                    }),
                }
            }

            SftpWirePacket::Write {
                id,
                handle,
                offset,
                data,
            } => {
                let id = *id;
                let offset = *offset;
                match self.handles.get_mut(handle) {
                    Some(SftpHandle::File(file, _)) => match file.seek(SeekFrom::Start(offset)) {
                        Err(e) => Ok(Self::status_err(id, &e)),
                        Ok(_) => match file.write_all(data) {
                            Err(e) => Ok(Self::status_err(id, &e)),
                            Ok(_) => Ok(Self::status_ok(id)),
                        },
                    },
                    _ => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::Failure,
                        message: "invalid handle".to_string(),
                    }),
                }
            }

            SftpWirePacket::Stat { id, path } | SftpWirePacket::Lstat { id, path } => {
                let id = *id;
                match self.resolve_path_checked(path, false) {
                    Err(_) => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::PermissionDenied,
                        message: "path escapes root".to_string(),
                    }),
                    Ok(full_path) => match fs::metadata(&full_path) {
                        Ok(meta) => Ok(SftpWirePacket::AttrsReply {
                            id,
                            attrs: FileAttrs::from_fs_metadata(&meta),
                        }),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                }
            }

            SftpWirePacket::Fstat { id, handle } => {
                let id = *id;
                match self.handles.get(handle) {
                    Some(SftpHandle::File(file, _)) => match file.metadata() {
                        Ok(meta) => Ok(SftpWirePacket::AttrsReply {
                            id,
                            attrs: FileAttrs::from_fs_metadata(&meta),
                        }),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                    _ => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::Failure,
                        message: "invalid handle".to_string(),
                    }),
                }
            }

            SftpWirePacket::Setstat { id, path, attrs } => {
                let id = *id;
                match self.resolve_path_checked(path, false) {
                    Err(_) => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::PermissionDenied,
                        message: "path escapes root".to_string(),
                    }),
                    Ok(full_path) => match Self::apply_attrs(&full_path, attrs) {
                        Ok(()) => Ok(Self::status_ok(id)),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                }
            }

            SftpWirePacket::Fsetstat { id, handle, attrs } => {
                let id = *id;
                match self.handles.get(handle) {
                    Some(SftpHandle::File(_, path)) => match Self::apply_attrs(path, attrs) {
                        Ok(()) => Ok(Self::status_ok(id)),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                    _ => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::Failure,
                        message: "invalid handle".to_string(),
                    }),
                }
            }

            SftpWirePacket::Opendir { id, path } => {
                let id = *id;
                let full_path = match self.resolve_path_checked(path, false) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                match fs::read_dir(&full_path) {
                    Err(e) => Ok(Self::status_err(id, &e)),
                    Ok(rd) => {
                        let mut entries = Vec::new();
                        for entry in rd {
                            let entry = match entry {
                                Err(e) => return Ok(Self::status_err(id, &e)),
                                Ok(e) => e,
                            };
                            let name = entry.file_name().to_string_lossy().to_string();
                            let attrs = entry
                                .metadata()
                                .map(|m| FileAttrs::from_fs_metadata(&m))
                                .unwrap_or_default();
                            entries.push(SftpNameEntry {
                                filename: name.clone(),
                                longname: name,
                                attrs,
                            });
                        }
                        entries.sort_unstable_by(|a, b| a.filename.cmp(&b.filename));
                        let handle = self.alloc_handle();
                        self.handles.insert(
                            handle.clone(),
                            SftpHandle::Dir(ReadDirState {
                                _path: full_path,
                                entries,
                                consumed: false,
                            }),
                        );
                        Ok(SftpWirePacket::Handle { id, handle })
                    }
                }
            }

            SftpWirePacket::Readdir { id, handle } => {
                let id = *id;
                match self.handles.get_mut(handle) {
                    Some(SftpHandle::Dir(state)) => {
                        if state.consumed || state.entries.is_empty() {
                            state.consumed = true;
                            Ok(SftpWirePacket::Status {
                                id,
                                status: SftpStatus::Eof,
                                message: SftpStatus::Eof.message().to_string(),
                            })
                        } else {
                            let entries = state.entries.drain(..).collect();
                            state.consumed = true;
                            Ok(SftpWirePacket::Name { id, entries })
                        }
                    }
                    _ => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::Failure,
                        message: "invalid handle".to_string(),
                    }),
                }
            }

            SftpWirePacket::Remove { id, filename } => {
                let id = *id;
                match self.resolve_path_checked(filename, false) {
                    Err(_) => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::PermissionDenied,
                        message: "path escapes root".to_string(),
                    }),
                    Ok(p) => match fs::remove_file(&p) {
                        Ok(_) => Ok(Self::status_ok(id)),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                }
            }

            SftpWirePacket::Mkdir { id, path, .. } => {
                let id = *id;
                match self.resolve_path_checked(path, false) {
                    Err(_) => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::PermissionDenied,
                        message: "path escapes root".to_string(),
                    }),
                    Ok(p) => match fs::create_dir_all(&p) {
                        Ok(_) => Ok(Self::status_ok(id)),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                }
            }

            SftpWirePacket::Rmdir { id, path } => {
                let id = *id;
                match self.resolve_path_checked(path, false) {
                    Err(_) => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::PermissionDenied,
                        message: "path escapes root".to_string(),
                    }),
                    Ok(p) => match fs::remove_dir(&p) {
                        Ok(_) => Ok(Self::status_ok(id)),
                        Err(e) => Ok(Self::status_err(id, &e)),
                    },
                }
            }

            SftpWirePacket::Realpath { id, path } => {
                let id = *id;
                match self.resolve_path_checked(path, false) {
                    Err(_) => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::PermissionDenied,
                        message: "path escapes root".to_string(),
                    }),
                    Ok(full_path) => {
                        let name = match self.display_path(&full_path) {
                            Ok(name) => name,
                            Err(_) => {
                                return Ok(SftpWirePacket::Status {
                                    id,
                                    status: SftpStatus::PermissionDenied,
                                    message: "path escapes root".to_string(),
                                });
                            }
                        };
                        Ok(SftpWirePacket::Name {
                            id,
                            entries: vec![SftpNameEntry {
                                filename: name.clone(),
                                longname: name,
                                attrs: FileAttrs::default(),
                            }],
                        })
                    }
                }
            }

            SftpWirePacket::Rename {
                id,
                oldpath,
                newpath,
            } => {
                let id = *id;
                let old = match self.resolve_path_checked(oldpath, false) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                let new = match self.resolve_path_checked(newpath, true) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                match fs::rename(&old, &new) {
                    Ok(_) => Ok(Self::status_ok(id)),
                    Err(e) => Ok(Self::status_err(id, &e)),
                }
            }

            SftpWirePacket::Readlink { id, path } => {
                let id = *id;
                let full_path = match self.resolve_path_checked(path, false) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                match fs::read_link(&full_path) {
                    Ok(target) => {
                        let target_str = target.to_string_lossy().to_string();
                        Ok(SftpWirePacket::Name {
                            id,
                            entries: vec![SftpNameEntry {
                                filename: target_str.clone(),
                                longname: target_str,
                                attrs: FileAttrs::default(),
                            }],
                        })
                    }
                    Err(e) => Ok(Self::status_err(id, &e)),
                }
            }

            SftpWirePacket::Symlink {
                id,
                target_path,
                link_path,
            } => {
                let id = *id;
                let link_full = match self.resolve_path_checked(link_path, true) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                let target_full = match self.resolve_path_checked(target_path, true) {
                    Err(_) => {
                        return Ok(SftpWirePacket::Status {
                            id,
                            status: SftpStatus::PermissionDenied,
                            message: "path escapes root".to_string(),
                        });
                    }
                    Ok(p) => p,
                };
                match std::os::unix::fs::symlink(&target_full, &link_full) {
                    Ok(_) => Ok(Self::status_ok(id)),
                    Err(e) => Ok(Self::status_err(id, &e)),
                }
            }

            SftpWirePacket::Extended {
                id,
                extension_name,
                data,
            } => {
                let id = *id;
                match extension_name.as_str() {
                    "posix-rename@openssh.com" => self.handle_posix_rename(id, data),
                    "statvfs@openssh.com" => self.handle_statvfs(id, data),
                    "hardlink@openssh.com" => self.handle_hardlink(id, data),
                    "fsync@openssh.com" => self.handle_fsync(id, data),
                    _ => Ok(SftpWirePacket::Status {
                        id,
                        status: SftpStatus::Unsupported,
                        message: format!("unknown extension: {extension_name}"),
                    }),
                }
            }

            // Unsupported or server→client packets
            _ => Ok(SftpWirePacket::Status {
                id: 0,
                status: SftpStatus::Unsupported,
                message: SftpStatus::Unsupported.message().to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// SftpFramer — streaming framer that yields complete packets
// ---------------------------------------------------------------------------

/// Buffers incoming bytes and yields complete `SftpWirePacket` frames.
pub struct SftpFramer {
    buf: Vec<u8>,
}

impl SftpFramer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns the next complete packet, or `None` if more data is needed.
    pub fn next_packet(&mut self) -> Result<Option<SftpWirePacket>, RusshError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buf.drain(..4 + len).collect();
        Ok(Some(SftpWirePacket::decode(&frame)?))
    }
}

impl Default for SftpFramer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    use russh_channel::{Channel, ChannelKind};

    use super::{SftpClient, SftpFileServer, SftpStatus, SftpWirePacket};

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

    #[cfg(unix)]
    #[test]
    fn realpath_does_not_leak_host_paths() {
        use std::os::unix::fs::symlink;

        let mut root = env::temp_dir();
        root.push("russh_sftp_realpath_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(root.join("nested")).expect("root should be created");
        fs::write(root.join("nested/file.txt"), b"x").expect("file should be created");

        let outside = root.with_extension("outside");
        if outside.exists() {
            fs::remove_dir_all(&outside).expect("outside cleanup should succeed");
        }
        fs::create_dir_all(&outside).expect("outside should be created");
        symlink(&outside, root.join("escape")).expect("symlink should be created");

        let mut server = SftpFileServer::new(&root);
        let packet = server
            .process(&SftpWirePacket::Realpath {
                id: 1,
                path: "/nested/file.txt".to_string(),
            })
            .expect("realpath should succeed");

        match packet {
            SftpWirePacket::Name { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].filename, "/nested/file.txt");
            }
            other => panic!("unexpected packet: {other:?}"),
        }

        let packet = server
            .process(&SftpWirePacket::Realpath {
                id: 2,
                path: "/escape".to_string(),
            })
            .expect("realpath should respond");
        match packet {
            SftpWirePacket::Status { status, .. } => {
                assert_eq!(status, SftpStatus::PermissionDenied);
            }
            other => panic!("unexpected packet: {other:?}"),
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
        fs::remove_dir_all(&outside).expect("outside cleanup should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let mut root = env::temp_dir();
        root.push("russh_sftp_symlink_escape_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let outside = root.with_extension("outside");
        if outside.exists() {
            fs::remove_dir_all(&outside).expect("outside cleanup should succeed");
        }
        fs::create_dir_all(&outside).expect("outside should be created");
        symlink(&outside, root.join("escape")).expect("symlink should be created");

        let mut server = SftpFileServer::new(&root);
        let packet = server
            .process(&SftpWirePacket::Open {
                id: 7,
                filename: "escape/pwned.txt".to_string(),
                pflags: super::open_flags::WRITE | super::open_flags::CREAT,
                attrs: Default::default(),
            })
            .expect("open should respond");

        match packet {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(id, 7);
                assert_eq!(status, SftpStatus::PermissionDenied);
            }
            other => panic!("unexpected packet: {other:?}"),
        }

        assert!(!outside.join("pwned.txt").exists());

        fs::remove_dir_all(&root).expect("cleanup should succeed");
        fs::remove_dir_all(&outside).expect("outside cleanup should succeed");
    }

    #[test]
    fn symlink_wire_round_trip() {
        let pkt = SftpWirePacket::Symlink {
            id: 42,
            target_path: "/data/target.txt".to_string(),
            link_path: "/data/link.txt".to_string(),
        };
        let encoded = pkt.encode();
        let decoded = SftpWirePacket::decode(&encoded).expect("decode should succeed");
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn readlink_wire_round_trip() {
        let pkt = SftpWirePacket::Readlink {
            id: 99,
            path: "/some/symlink".to_string(),
        };
        let encoded = pkt.encode();
        let decoded = SftpWirePacket::decode(&encoded).expect("decode should succeed");
        assert_eq!(pkt, decoded);
    }

    #[cfg(unix)]
    #[test]
    fn sftp_server_symlink_readlink_flow() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_symlink_readlink_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");
        fs::write(root.join("target.txt"), b"hello").expect("file should be created");

        let mut server = SftpFileServer::new(&root);

        // Create a symlink: link.txt -> target.txt
        let response = server
            .process(&SftpWirePacket::Symlink {
                id: 1,
                target_path: "target.txt".to_string(),
                link_path: "link.txt".to_string(),
            })
            .expect("symlink should succeed");
        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 1);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        // Verify symlink exists on disk
        assert!(
            root.join("link.txt")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // Readlink to verify the target
        let response = server
            .process(&SftpWirePacket::Readlink {
                id: 2,
                path: "link.txt".to_string(),
            })
            .expect("readlink should succeed");
        match response {
            SftpWirePacket::Name { id, entries } => {
                assert_eq!(id, 2);
                assert_eq!(entries.len(), 1);
                // The readlink target should contain the resolved path to target.txt
                assert!(
                    entries[0].filename.contains("target.txt"),
                    "expected target.txt in readlink result, got: {}",
                    entries[0].filename
                );
            }
            other => panic!("expected Name, got: {other:?}"),
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn extended_wire_round_trip() {
        let mut ext_data = Vec::new();
        super::sftp_write_string(&mut ext_data, b"old.txt");
        super::sftp_write_string(&mut ext_data, b"new.txt");

        let pkt = SftpWirePacket::Extended {
            id: 10,
            extension_name: "posix-rename@openssh.com".to_string(),
            data: ext_data.clone(),
        };
        let encoded = pkt.encode();
        let decoded = SftpWirePacket::decode(&encoded).expect("decode should succeed");
        assert_eq!(pkt, decoded);

        // ExtendedReply round-trip
        let reply = SftpWirePacket::ExtendedReply {
            id: 10,
            data: vec![1, 2, 3, 4],
        };
        let encoded = reply.encode();
        let decoded = SftpWirePacket::decode(&encoded).expect("decode should succeed");
        assert_eq!(reply, decoded);
    }

    #[test]
    fn version_response_includes_extensions() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_ext_version_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);
        let response = server
            .process(&SftpWirePacket::Init { version: 3 })
            .expect("init should succeed");

        match &response {
            SftpWirePacket::Version {
                version,
                extensions,
            } => {
                assert_eq!(*version, 3);
                let names: Vec<&str> = extensions.iter().map(|(n, _)| n.as_str()).collect();
                assert!(names.contains(&"posix-rename@openssh.com"));
                assert!(names.contains(&"statvfs@openssh.com"));
                assert!(names.contains(&"hardlink@openssh.com"));
                assert!(names.contains(&"fsync@openssh.com"));
            }
            other => panic!("expected Version, got: {other:?}"),
        }

        // Verify round-trip: encode then decode preserves extensions
        let encoded = response.encode();
        let decoded = SftpWirePacket::decode(&encoded).expect("decode should succeed");
        assert_eq!(response, decoded);

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn extended_posix_rename_works() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_ext_posix_rename_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");
        fs::write(root.join("old.txt"), b"data").expect("file should be created");

        let mut server = SftpFileServer::new(&root);

        let mut ext_data = Vec::new();
        super::sftp_write_string(&mut ext_data, b"old.txt");
        super::sftp_write_string(&mut ext_data, b"new.txt");

        let response = server
            .process(&SftpWirePacket::Extended {
                id: 1,
                extension_name: "posix-rename@openssh.com".to_string(),
                data: ext_data,
            })
            .expect("posix-rename should succeed");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 1);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        assert!(!root.join("old.txt").exists());
        assert!(root.join("new.txt").exists());
        assert_eq!(fs::read(root.join("new.txt")).unwrap(), b"data");

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn extended_hardlink_works() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_ext_hardlink_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");
        fs::write(root.join("original.txt"), b"content").expect("file should be created");

        let mut server = SftpFileServer::new(&root);

        let mut ext_data = Vec::new();
        super::sftp_write_string(&mut ext_data, b"original.txt");
        super::sftp_write_string(&mut ext_data, b"linked.txt");

        let response = server
            .process(&SftpWirePacket::Extended {
                id: 2,
                extension_name: "hardlink@openssh.com".to_string(),
                data: ext_data,
            })
            .expect("hardlink should succeed");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 2);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        assert!(root.join("original.txt").exists());
        assert!(root.join("linked.txt").exists());
        assert_eq!(fs::read(root.join("linked.txt")).unwrap(), b"content");

        // Verify hard link (same inode)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let orig_ino = fs::metadata(root.join("original.txt")).unwrap().ino();
            let link_ino = fs::metadata(root.join("linked.txt")).unwrap().ino();
            assert_eq!(orig_ino, link_ino);
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn extended_fsync_works() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_ext_fsync_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);

        // Open a file for writing
        let open_resp = server
            .process(&SftpWirePacket::Open {
                id: 1,
                filename: "fsync_test.txt".to_string(),
                pflags: super::open_flags::WRITE | super::open_flags::CREAT,
                attrs: Default::default(),
            })
            .expect("open should succeed");
        let handle = match &open_resp {
            SftpWirePacket::Handle { handle, .. } => handle.clone(),
            other => panic!("expected Handle, got: {other:?}"),
        };

        // Write some data
        server
            .process(&SftpWirePacket::Write {
                id: 2,
                handle: handle.clone(),
                offset: 0,
                data: b"test data".to_vec(),
            })
            .expect("write should succeed");

        // Fsync the handle
        let mut ext_data = Vec::new();
        super::sftp_write_string(&mut ext_data, &handle);

        let response = server
            .process(&SftpWirePacket::Extended {
                id: 3,
                extension_name: "fsync@openssh.com".to_string(),
                data: ext_data,
            })
            .expect("fsync should succeed");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 3);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        // Close handle
        server
            .process(&SftpWirePacket::Close { id: 4, handle })
            .expect("close should succeed");

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn extended_statvfs_returns_reply() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_ext_statvfs_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);

        let mut ext_data = Vec::new();
        super::sftp_write_string(&mut ext_data, b"/");

        let response = server
            .process(&SftpWirePacket::Extended {
                id: 5,
                extension_name: "statvfs@openssh.com".to_string(),
                data: ext_data,
            })
            .expect("statvfs should succeed");

        match &response {
            SftpWirePacket::ExtendedReply { id, data } => {
                assert_eq!(*id, 5);
                // 11 uint64 values = 88 bytes
                assert_eq!(data.len(), 88);
            }
            other => panic!("expected ExtendedReply, got: {other:?}"),
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn extended_unknown_returns_unsupported() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_ext_unknown_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);

        let response = server
            .process(&SftpWirePacket::Extended {
                id: 99,
                extension_name: "nonexistent@example.com".to_string(),
                data: Vec::new(),
            })
            .expect("unknown extension should respond");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 99);
                assert_eq!(*status, SftpStatus::Unsupported);
            }
            other => panic!("expected Status Unsupported, got: {other:?}"),
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn setstat_sets_permissions_on_path() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_setstat_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);

        // Create a file via SFTP
        let open_resp = server
            .process(&SftpWirePacket::Open {
                id: 1,
                filename: "target.txt".to_string(),
                pflags: super::open_flags::WRITE | super::open_flags::CREAT,
                attrs: Default::default(),
            })
            .expect("open should succeed");
        let handle = match &open_resp {
            SftpWirePacket::Handle { handle, .. } => handle.clone(),
            other => panic!("expected Handle, got: {other:?}"),
        };
        server
            .process(&SftpWirePacket::Write {
                id: 2,
                handle: handle.clone(),
                offset: 0,
                data: b"hello".to_vec(),
            })
            .expect("write should succeed");
        server
            .process(&SftpWirePacket::Close { id: 3, handle })
            .expect("close should succeed");

        // Apply setstat with permissions
        let response = server
            .process(&SftpWirePacket::Setstat {
                id: 4,
                path: "target.txt".to_string(),
                attrs: super::FileAttrs {
                    permissions: Some(0o644),
                    ..Default::default()
                },
            })
            .expect("setstat should succeed");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 4);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(root.join("target.txt")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn fsetstat_on_open_handle_succeeds() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_fsetstat_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);

        // Open a file for writing
        let open_resp = server
            .process(&SftpWirePacket::Open {
                id: 1,
                filename: "fsetstat_file.txt".to_string(),
                pflags: super::open_flags::WRITE | super::open_flags::CREAT,
                attrs: Default::default(),
            })
            .expect("open should succeed");
        let handle = match &open_resp {
            SftpWirePacket::Handle { handle, .. } => handle.clone(),
            other => panic!("expected Handle, got: {other:?}"),
        };

        // Write some data
        server
            .process(&SftpWirePacket::Write {
                id: 2,
                handle: handle.clone(),
                offset: 0,
                data: b"hello world".to_vec(),
            })
            .expect("write should succeed");

        // Fsetstat: set permissions via handle
        let response = server
            .process(&SftpWirePacket::Fsetstat {
                id: 3,
                handle: handle.clone(),
                attrs: super::FileAttrs {
                    permissions: Some(0o600),
                    ..Default::default()
                },
            })
            .expect("fsetstat should succeed");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 3);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        // Verify permissions were applied
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(root.join("fsetstat_file.txt")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Fsetstat: truncate via handle
        let response = server
            .process(&SftpWirePacket::Fsetstat {
                id: 4,
                handle: handle.clone(),
                attrs: super::FileAttrs {
                    size: Some(5),
                    ..Default::default()
                },
            })
            .expect("fsetstat truncate should succeed");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 4);
                assert_eq!(*status, SftpStatus::Ok);
            }
            other => panic!("expected Status Ok, got: {other:?}"),
        }

        // Close and verify truncation
        server
            .process(&SftpWirePacket::Close {
                id: 5,
                handle: handle.clone(),
            })
            .expect("close should succeed");

        let content = fs::read(root.join("fsetstat_file.txt")).unwrap();
        assert_eq!(content, b"hello");

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }

    #[test]
    fn fsetstat_invalid_handle_returns_failure() {
        let mut root = env::temp_dir();
        root.push("russh_sftp_fsetstat_bad_handle_test");
        if root.exists() {
            fs::remove_dir_all(&root).expect("cleanup should succeed");
        }
        fs::create_dir_all(&root).expect("root should be created");

        let mut server = SftpFileServer::new(&root);

        let response = server
            .process(&SftpWirePacket::Fsetstat {
                id: 1,
                handle: vec![0xFF, 0xFF, 0xFF, 0xFF],
                attrs: super::FileAttrs {
                    permissions: Some(0o644),
                    ..Default::default()
                },
            })
            .expect("fsetstat with bad handle should respond");

        match &response {
            SftpWirePacket::Status { id, status, .. } => {
                assert_eq!(*id, 1);
                assert_eq!(*status, SftpStatus::Failure);
            }
            other => panic!("expected Status Failure, got: {other:?}"),
        }

        fs::remove_dir_all(&root).expect("cleanup should succeed");
    }
}
