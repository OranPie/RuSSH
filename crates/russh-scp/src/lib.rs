//! SCP compatibility primitives for RuSSH.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use russh_channel::Channel;
use russh_core::{RusshError, RusshErrorCategory};

/// SCP transfer direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScpDirection {
    Upload,
    Download,
}

/// Copy behavior controls for SCP operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScpCopyOptions {
    pub overwrite: bool,
    pub recursive: bool,
    pub preserve_permissions: bool,
    pub follow_symlinks: bool,
    pub buffer_size: usize,
}

impl ScpCopyOptions {
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            overwrite: true,
            recursive: false,
            preserve_permissions: true,
            follow_symlinks: false,
            buffer_size: 128 * 1024,
        }
    }
}

impl Default for ScpCopyOptions {
    fn default() -> Self {
        Self::secure_defaults()
    }
}

/// Aggregated transfer statistics for recursive copy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScpTransferStats {
    pub files_copied: u64,
    pub directories_created: u64,
    pub bytes_copied: u64,
}

/// SCP client façade bound to a session channel.
#[derive(Clone, Debug)]
pub struct ScpClient {
    pub channel: Channel,
}

impl ScpClient {
    #[must_use]
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    pub fn copy(
        &self,
        source: impl AsRef<Path>,
        target: impl AsRef<Path>,
        direction: ScpDirection,
    ) -> Result<u64, RusshError> {
        self.copy_with_options(source, target, direction, ScpCopyOptions::secure_defaults())
    }

    pub fn copy_with_options(
        &self,
        source: impl AsRef<Path>,
        target: impl AsRef<Path>,
        direction: ScpDirection,
        options: ScpCopyOptions,
    ) -> Result<u64, RusshError> {
        let source = source.as_ref();
        let target = target.as_ref();

        let source_metadata = if options.follow_symlinks {
            fs::metadata(source)
        } else {
            fs::symlink_metadata(source)
        }
        .map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("source path {:?} cannot be read: {error}", source),
            )
        })?;

        if source_metadata.is_dir() {
            if options.recursive {
                return self
                    .recursive_copy_with_options(source, target, options)
                    .map(|stats| stats.bytes_copied);
            }
            return Err(RusshError::new(
                RusshErrorCategory::Io,
                "source is a directory; set recursive=true for directory copy",
            ));
        }

        if source_metadata.file_type().is_symlink() && !options.follow_symlinks {
            return Err(RusshError::new(
                RusshErrorCategory::Io,
                "source is a symlink; set follow_symlinks=true to copy symlink target",
            ));
        }

        if target.exists() && !options.overwrite {
            return Err(RusshError::new(
                RusshErrorCategory::Io,
                format!("target path {:?} already exists", target),
            ));
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to create parent {:?}: {error}", parent),
                )
            })?;
        }

        let bytes = copy_file_streaming(source, target, options.buffer_size).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("scp {:?} {:?} failed: {error}", direction, source),
            )
        })?;

        if options.preserve_permissions {
            fs::set_permissions(target, source_metadata.permissions()).map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to preserve permissions on {:?}: {error}", target),
                )
            })?;
        }

        Ok(bytes)
    }

    pub fn recursive_copy(
        &self,
        source_dir: impl Into<PathBuf>,
        target_dir: impl Into<PathBuf>,
    ) -> Result<(), RusshError> {
        let _stats = self.recursive_copy_with_options(
            source_dir,
            target_dir,
            ScpCopyOptions::secure_defaults(),
        )?;
        Ok(())
    }

    pub fn recursive_copy_with_options(
        &self,
        source_dir: impl Into<PathBuf>,
        target_dir: impl Into<PathBuf>,
        mut options: ScpCopyOptions,
    ) -> Result<ScpTransferStats, RusshError> {
        let source_dir = source_dir.into();
        let target_dir = target_dir.into();
        options.recursive = true;

        let source_metadata = if options.follow_symlinks {
            fs::metadata(&source_dir)
        } else {
            fs::symlink_metadata(&source_dir)
        }
        .map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to stat source {:?}: {error}", source_dir),
            )
        })?;
        if !source_metadata.is_dir() {
            return Err(RusshError::new(
                RusshErrorCategory::Io,
                format!("source {:?} is not a directory", source_dir),
            ));
        }

        ensure_target_not_inside_source(&source_dir, &target_dir)?;

        fs::create_dir_all(&target_dir).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to create target {:?}: {error}", target_dir),
            )
        })?;
        let mut stats = ScpTransferStats {
            files_copied: 0,
            directories_created: 1,
            bytes_copied: 0,
        };
        if options.preserve_permissions {
            fs::set_permissions(&target_dir, source_metadata.permissions()).map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!(
                        "failed to preserve permissions on {:?}: {error}",
                        target_dir
                    ),
                )
            })?;
        }

        self.recursive_copy_inner(&source_dir, &target_dir, options, &mut stats)?;
        Ok(stats)
    }

    fn recursive_copy_inner(
        &self,
        source_dir: &Path,
        target_dir: &Path,
        options: ScpCopyOptions,
        stats: &mut ScpTransferStats,
    ) -> Result<(), RusshError> {
        let _ = &self.channel;

        for entry in fs::read_dir(source_dir).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("failed to list {:?}: {error}", source_dir),
            )
        })? {
            let entry = entry.map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to read entry: {error}"),
                )
            })?;
            let source_path = entry.path();
            let target_path = target_dir.join(entry.file_name());
            let metadata = if options.follow_symlinks {
                fs::metadata(&source_path)
            } else {
                fs::symlink_metadata(&source_path)
            }
            .map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to stat {:?}: {error}", source_path),
                )
            })?;

            if metadata.is_dir() {
                fs::create_dir_all(&target_path).map_err(|error| {
                    RusshError::new(
                        RusshErrorCategory::Io,
                        format!("failed to create directory {:?}: {error}", target_path),
                    )
                })?;
                stats.directories_created = stats.directories_created.saturating_add(1);
                if options.preserve_permissions {
                    fs::set_permissions(&target_path, metadata.permissions()).map_err(|error| {
                        RusshError::new(
                            RusshErrorCategory::Io,
                            format!(
                                "failed to preserve permissions on directory {:?}: {error}",
                                target_path
                            ),
                        )
                    })?;
                }
                self.recursive_copy_inner(&source_path, &target_path, options, stats)?;
            } else {
                if metadata.file_type().is_symlink() && !options.follow_symlinks {
                    return Err(RusshError::new(
                        RusshErrorCategory::Io,
                        format!(
                            "encountered symlink {:?} while follow_symlinks=false",
                            source_path
                        ),
                    ));
                }
                let bytes = self.copy_with_options(
                    &source_path,
                    &target_path,
                    ScpDirection::Upload,
                    ScpCopyOptions {
                        recursive: false,
                        ..options
                    },
                )?;
                stats.files_copied = stats.files_copied.saturating_add(1);
                stats.bytes_copied = stats.bytes_copied.saturating_add(bytes);
            }
        }

        Ok(())
    }
}

fn copy_file_streaming(source: &Path, target: &Path, buffer_size: usize) -> std::io::Result<u64> {
    let mut source_file = fs::File::open(source)?;
    let mut target_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(target)?;

    let mut total = 0u64;
    let mut buffer = vec![0u8; buffer_size.max(4 * 1024)];
    loop {
        let read = source_file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        target_file.write_all(&buffer[..read])?;
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }

    target_file.flush()?;
    Ok(total)
}

fn ensure_target_not_inside_source(source: &Path, target: &Path) -> Result<(), RusshError> {
    let source_absolute = fs::canonicalize(source).map_err(|error| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to canonicalize source {:?}: {error}", source),
        )
    })?;
    let target_absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                RusshError::new(
                    RusshErrorCategory::Io,
                    format!("failed to resolve current directory: {error}"),
                )
            })?
            .join(target)
    };
    if target_absolute.starts_with(&source_absolute) {
        return Err(RusshError::new(
            RusshErrorCategory::Io,
            format!(
                "refusing recursive copy into source subtree: source {:?}, target {:?}",
                source, target
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use russh_channel::{Channel, ChannelKind};

    use super::{ScpClient, ScpCopyOptions, ScpDirection};

    #[test]
    fn file_copy_succeeds() {
        let tmp = env::temp_dir().join("russh_scp_test");
        if tmp.exists() {
            fs::remove_dir_all(&tmp).expect("cleanup should succeed");
        }
        fs::create_dir_all(&tmp).expect("tmp directory should be created");

        let source = tmp.join("src.txt");
        let target = tmp.join("dst.txt");
        fs::write(&source, b"scp-data").expect("source should be writable");

        let client = ScpClient::new(Channel::open(ChannelKind::Session));
        let bytes = client
            .copy(&source, &target, ScpDirection::Upload)
            .expect("copy should succeed");

        assert_eq!(bytes, 8);
        assert_eq!(
            fs::read(&target).expect("target read should succeed"),
            b"scp-data"
        );

        fs::remove_dir_all(&tmp).expect("cleanup should succeed");
    }

    #[test]
    fn copy_respects_no_overwrite_option() {
        let tmp = env::temp_dir().join("russh_scp_overwrite_test");
        if tmp.exists() {
            fs::remove_dir_all(&tmp).expect("cleanup should succeed");
        }
        fs::create_dir_all(&tmp).expect("tmp directory should be created");

        let source = tmp.join("src.txt");
        let target = tmp.join("dst.txt");
        fs::write(&source, b"new-data").expect("source should be writable");
        fs::write(&target, b"old-data").expect("target should be writable");

        let client = ScpClient::new(Channel::open(ChannelKind::Session));
        let error = client
            .copy_with_options(
                &source,
                &target,
                ScpDirection::Upload,
                ScpCopyOptions {
                    overwrite: false,
                    ..ScpCopyOptions::secure_defaults()
                },
            )
            .expect_err("copy should fail when overwrite is disabled");
        assert_eq!(error.category(), russh_core::RusshErrorCategory::Io);
        assert_eq!(
            fs::read(&target).expect("target read should succeed"),
            b"old-data"
        );

        fs::remove_dir_all(&tmp).expect("cleanup should succeed");
    }

    #[test]
    fn recursive_copy_reports_stats() {
        let tmp = env::temp_dir().join("russh_scp_recursive_test");
        if tmp.exists() {
            fs::remove_dir_all(&tmp).expect("cleanup should succeed");
        }
        let source = tmp.join("source");
        let target = tmp.join("target");
        fs::create_dir_all(source.join("nested")).expect("source tree should be created");
        fs::write(source.join("root.txt"), b"root").expect("file write should succeed");
        fs::write(source.join("nested").join("child.txt"), b"child")
            .expect("nested file write should succeed");

        let client = ScpClient::new(Channel::open(ChannelKind::Session));
        let stats = client
            .recursive_copy_with_options(&source, &target, ScpCopyOptions::secure_defaults())
            .expect("recursive copy should succeed");

        assert_eq!(stats.files_copied, 2);
        assert_eq!(stats.directories_created, 2);
        assert_eq!(stats.bytes_copied, 9);
        assert_eq!(
            fs::read(target.join("nested").join("child.txt")).expect("child file should exist"),
            b"child"
        );

        fs::remove_dir_all(&tmp).expect("cleanup should succeed");
    }

    #[test]
    fn recursive_copy_rejects_target_inside_source() {
        let tmp = env::temp_dir().join("russh_scp_target_guard_test");
        if tmp.exists() {
            fs::remove_dir_all(&tmp).expect("cleanup should succeed");
        }
        let source = tmp.join("source");
        let nested_target = source.join("nested-target");
        fs::create_dir_all(source.join("sub")).expect("source tree should be created");
        fs::write(source.join("sub").join("file.txt"), b"data").expect("file write should succeed");

        let client = ScpClient::new(Channel::open(ChannelKind::Session));
        let error = client
            .recursive_copy_with_options(&source, &nested_target, ScpCopyOptions::secure_defaults())
            .expect_err("copy into subtree should be rejected");
        assert_eq!(error.category(), russh_core::RusshErrorCategory::Io);

        fs::remove_dir_all(&tmp).expect("cleanup should succeed");
    }
}
