use std::{fs, io, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReleaseEvidencePathKind {
    Missing,
    RegularFile,
    Symlink,
    Directory,
    Other,
}

impl ReleaseEvidencePathKind {
    pub(super) fn scaffold_failure(self, file_name: &str) -> String {
        match self {
            Self::Symlink => {
                format!("{file_name}: scaffold file must be a regular file, got symlink")
            }
            Self::Directory => {
                format!("{file_name}: scaffold file must be a regular file, got directory")
            }
            Self::Other => format!("{file_name}: scaffold file must be a regular file"),
            Self::Missing | Self::RegularFile => {
                unreachable!("missing and regular scaffold paths are not unsafe")
            }
        }
    }

    pub(super) fn scaffold_io_error(self, path: &Path) -> io::Error {
        let path = path.to_string_lossy();
        match self {
            Self::Symlink => io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "release evidence scaffold file must be a regular file, got symlink: {path}"
                ),
            ),
            Self::Directory => io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "release evidence scaffold file must be a regular file, got directory: {path}"
                ),
            ),
            Self::Other => io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("release evidence scaffold file must be a regular file: {path}"),
            ),
            Self::Missing | Self::RegularFile => {
                unreachable!("missing and regular scaffold paths are not unsafe")
            }
        }
    }
}

pub(super) fn release_evidence_path_kind(
    path: &Path,
) -> Result<ReleaseEvidencePathKind, io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                Ok(ReleaseEvidencePathKind::Symlink)
            } else if file_type.is_dir() {
                Ok(ReleaseEvidencePathKind::Directory)
            } else if file_type.is_file() {
                Ok(ReleaseEvidencePathKind::RegularFile)
            } else {
                Ok(ReleaseEvidencePathKind::Other)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(ReleaseEvidencePathKind::Missing)
        }
        Err(error) => Err(error),
    }
}
