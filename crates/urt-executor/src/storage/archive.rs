//! Validation of downloaded build artefacts.
//!
//! Object storage can answer a `GET` with an error document instead of the
//! object: a 503 from an S3-compatible endpoint carries a few hundred bytes of
//! XML. Written to `code.tar.gz` and mounted into a container, that document
//! produces a runtime that starts and never listens. Every artefact fetched
//! from storage is therefore checked against the format its key implies before
//! anything else is allowed to use it.

use crate::error::{ExecutorError, Result};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// Bytes of a response body echoed into an error message.
const PREVIEW_LIMIT: usize = 300;

/// A tar header block is 512 bytes; that is also the most we need to read from
/// a file on disk to decide whether it is a plausible archive.
const TAR_BLOCK_SIZE: usize = 512;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Archive format expected of an artefact, inferred from its storage key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Gzip,
    Zstd,
    Tar,
    /// The key carries no recognised archive extension. Only the checks that
    /// hold for any payload are applied.
    Unknown,
}

impl ArchiveFormat {
    /// Infer the expected format from a storage key or file name.
    pub fn from_path(path: &str) -> Self {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".gz") {
            Self::Gzip
        } else if lower.ends_with(".tar.zst") || lower.ends_with(".zst") {
            Self::Zstd
        } else if lower.ends_with(".tar") {
            Self::Tar
        } else {
            Self::Unknown
        }
    }

    /// Identify the format from the leading bytes of a payload.
    ///
    /// Runtime images name every build artefact `code.tar.gz` whatever
    /// compression produced it, so the name cannot be trusted to say what is
    /// inside one. Returns [`ArchiveFormat::Unknown`] when nothing matches.
    pub fn detect(head: &[u8]) -> Self {
        if head.starts_with(&GZIP_MAGIC) {
            Self::Gzip
        } else if head.starts_with(&ZSTD_MAGIC) {
            Self::Zstd
        } else if tar_header_is_plausible(head) {
            Self::Tar
        } else {
            Self::Unknown
        }
    }

    /// The extension an artefact of this format should be stored under.
    pub fn extension(&self) -> Option<&'static str> {
        match self {
            Self::Gzip => Some("tar.gz"),
            Self::Zstd => Some("tar.zst"),
            Self::Tar => Some("tar"),
            Self::Unknown => None,
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::Tar => "tar",
            Self::Unknown => "archive",
        }
    }
}

/// Validate an artefact held in memory.
///
/// `source_hint` is the storage key or file name; its extension selects the
/// format check and it is named in any error.
///
/// Downloads stream to disk and go through `validate_archive_file`; this is the
/// entry point for a payload that is already in memory.
#[allow(dead_code)]
pub fn validate_archive_bytes(source_hint: &str, data: &[u8]) -> Result<()> {
    validate_archive_head(source_hint, data, data.len() as u64)
}

/// Validate an artefact already written to disk, returning its size in bytes.
///
/// Only the leading block is read, so this stays cheap for multi-megabyte
/// builds.
pub async fn validate_archive_file(source_hint: &str, path: &Path) -> Result<u64> {
    let file = tokio::fs::File::open(path).await.map_err(|e| {
        ExecutorError::Storage(format!(
            "Failed to open downloaded artefact '{}': {}",
            path.display(),
            e
        ))
    })?;

    let size = file
        .metadata()
        .await
        .map_err(|e| {
            ExecutorError::Storage(format!(
                "Failed to stat downloaded artefact '{}': {}",
                path.display(),
                e
            ))
        })?
        .len();

    let mut head = Vec::with_capacity(TAR_BLOCK_SIZE);
    file.take(TAR_BLOCK_SIZE as u64)
        .read_to_end(&mut head)
        .await
        .map_err(|e| {
            ExecutorError::Storage(format!(
                "Failed to read downloaded artefact '{}': {}",
                path.display(),
                e
            ))
        })?;

    validate_archive_head(source_hint, &head, size)?;
    Ok(size)
}

/// Identify the format of an artefact on disk from its leading bytes.
///
/// Returns [`ArchiveFormat::Unknown`] when the file cannot be read or nothing
/// matches, so a caller can fall back to what the file name implies.
pub async fn detect_archive_file(path: &Path) -> ArchiveFormat {
    let Ok(file) = tokio::fs::File::open(path).await else {
        return ArchiveFormat::Unknown;
    };

    let mut head = Vec::with_capacity(TAR_BLOCK_SIZE);
    if file
        .take(TAR_BLOCK_SIZE as u64)
        .read_to_end(&mut head)
        .await
        .is_err()
    {
        return ArchiveFormat::Unknown;
    }

    ArchiveFormat::detect(&head)
}

/// Core check, shared by the in-memory and on-disk entry points.
///
/// `head` is the leading bytes of the payload and `total_len` its full length,
/// which may be larger than `head`.
fn validate_archive_head(source_hint: &str, head: &[u8], total_len: u64) -> Result<()> {
    if total_len == 0 {
        return Err(ExecutorError::Storage(format!(
            "Downloaded artefact for '{}' is empty",
            source_hint
        )));
    }

    let format = ArchiveFormat::from_path(source_hint);
    let valid = match format {
        ArchiveFormat::Gzip => head.starts_with(&GZIP_MAGIC),
        ArchiveFormat::Zstd => head.starts_with(&ZSTD_MAGIC),
        ArchiveFormat::Tar => total_len >= TAR_BLOCK_SIZE as u64 && tar_header_is_plausible(head),
        ArchiveFormat::Unknown => !looks_like_error_document(head),
    };

    if valid {
        return Ok(());
    }

    Err(ExecutorError::Storage(format!(
        "Downloaded artefact for '{}' is not a valid {} archive ({} bytes){}: {}",
        source_hint,
        format.describe(),
        total_len,
        if looks_like_error_document(head) {
            ", it is an error document"
        } else {
            ""
        },
        body_preview(head)
    )))
}

/// Whether a payload opens like an XML or HTML document, which is how S3
/// endpoints report failure.
pub(crate) fn looks_like_error_document(data: &[u8]) -> bool {
    let head = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    head.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'<')
}

/// Render the leading bytes of a body for an error message: readable text where
/// the payload is text, a hex dump otherwise.
pub(crate) fn body_preview(data: &[u8]) -> String {
    if data.is_empty() {
        return "empty body".to_string();
    }

    let head = &data[..data.len().min(PREVIEW_LIMIT)];
    let printable = head
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();

    if printable * 10 < head.len() * 8 {
        let hex = head
            .iter()
            .take(16)
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(" ");
        return format!("first bytes {}", hex);
    }

    let mut text = String::with_capacity(head.len());
    let mut in_space = false;
    for ch in String::from_utf8_lossy(head).chars() {
        let ch = if ch.is_control() { ' ' } else { ch };
        if ch == ' ' {
            if in_space {
                continue;
            }
            in_space = true;
        } else {
            in_space = false;
        }
        text.push(ch);
    }

    let mut preview = text.trim().to_string();
    if data.len() > PREVIEW_LIMIT {
        preview.push_str(" ...");
    }
    preview
}

/// Whether a 512-byte block is a tar header, decided by its checksum field.
///
/// The checksum covers every byte of the block with the checksum field itself
/// read as spaces. Both the unsigned and the signed sum are accepted, since
/// historic implementations differ on whether the bytes are signed.
fn tar_header_is_plausible(block: &[u8]) -> bool {
    if block.len() < TAR_BLOCK_SIZE {
        return false;
    }

    let Some(declared) = parse_octal(&block[148..156]) else {
        return false;
    };

    let mut unsigned: u32 = 0;
    let mut signed: i32 = 0;
    for (index, byte) in block[..TAR_BLOCK_SIZE].iter().enumerate() {
        let byte = if (148..156).contains(&index) {
            b' '
        } else {
            *byte
        };
        unsigned += u32::from(byte);
        signed += i32::from(byte as i8);
    }

    declared == unsigned || i64::from(declared) == i64::from(signed)
}

/// Parse a NUL- or space-padded octal field from a tar header.
fn parse_octal(field: &[u8]) -> Option<u32> {
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ')
        .take_while(|byte| byte.is_ascii_digit())
        .collect();

    if digits.is_empty() {
        return None;
    }

    let text = std::str::from_utf8(&digits).ok()?;
    u32::from_str_radix(text, 8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    const S3_ERROR_BODY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>ServiceUnavailable</Code><Message>Service is unable to handle request.</Message></Error>"#;

    fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn tar_bytes() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let payload = b"function code";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "index.js", &payload[..])
            .unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn infers_format_from_extension() {
        assert_eq!(
            ArchiveFormat::from_path("builds/app/code.tar.gz"),
            ArchiveFormat::Gzip
        );
        assert_eq!(ArchiveFormat::from_path("code.TGZ"), ArchiveFormat::Gzip);
        assert_eq!(
            ArchiveFormat::from_path("cache/layer.tar.zst"),
            ArchiveFormat::Zstd
        );
        assert_eq!(ArchiveFormat::from_path("code.tar"), ArchiveFormat::Tar);
        assert_eq!(ArchiveFormat::from_path("manifest"), ArchiveFormat::Unknown);
    }

    #[test]
    fn accepts_real_gzip_archive() {
        let data = gzip_bytes(&tar_bytes());
        validate_archive_bytes("builds/app/code.tar.gz", &data).expect("gzip archive is valid");
    }

    #[test]
    fn accepts_real_tar_archive() {
        validate_archive_bytes("builds/app/code.tar", &tar_bytes()).expect("tar archive is valid");
    }

    #[test]
    fn accepts_zstd_layer() {
        let mut data = ZSTD_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 64]);
        validate_archive_bytes("cache/node_modules.tar.zst", &data).expect("zstd layer is valid");
    }

    #[test]
    fn rejects_s3_error_body_named_as_gzip() {
        let error = validate_archive_bytes("builds/app/code.tar.gz", S3_ERROR_BODY)
            .expect_err("error document must not pass as an archive");
        let message = error.to_string();
        assert!(message.contains("not a valid gzip archive"), "{}", message);
        assert!(message.contains("it is an error document"), "{}", message);
        assert!(message.contains("ServiceUnavailable"), "{}", message);
    }

    #[test]
    fn rejects_s3_error_body_named_as_tar() {
        let error = validate_archive_bytes("builds/app/code.tar", S3_ERROR_BODY)
            .expect_err("error document must not pass as an archive");
        assert!(error.to_string().contains("not a valid tar archive"));
    }

    #[test]
    fn rejects_error_document_without_extension() {
        let error = validate_archive_bytes("builds/app/code", S3_ERROR_BODY)
            .expect_err("error document must not pass as an artefact");
        assert!(error.to_string().contains("it is an error document"));
    }

    #[test]
    fn accepts_unknown_extension_with_binary_payload() {
        validate_archive_bytes("builds/app/code", &[0x00, 0x01, 0x02, 0x03])
            .expect("binary payload with no extension is accepted");
    }

    #[test]
    fn rejects_empty_payload() {
        let error = validate_archive_bytes("builds/app/code.tar.gz", &[])
            .expect_err("an empty artefact is never a build");
        assert!(error.to_string().contains("is empty"));
    }

    #[test]
    fn rejects_truncated_tar() {
        let mut data = tar_bytes();
        data.truncate(64);
        let error = validate_archive_bytes("builds/app/code.tar", &data)
            .expect_err("a tar shorter than one block is not an archive");
        assert!(error.to_string().contains("not a valid tar archive"));
    }

    #[test]
    fn rejects_html_error_page_named_as_gzip() {
        let body = b"<!DOCTYPE html><html><body>503 Service Unavailable</body></html>";
        let error = validate_archive_bytes("builds/app/code.tar.gz", body)
            .expect_err("HTML error pages are not archives");
        assert!(error.to_string().contains("it is an error document"));
    }

    #[test]
    fn detects_error_documents_with_leading_whitespace_and_bom() {
        assert!(looks_like_error_document(
            b"\xef\xbb\xbf  \n<?xml version=\"1.0\"?>"
        ));
        assert!(!looks_like_error_document(&GZIP_MAGIC));
        assert!(!looks_like_error_document(&[]));
    }

    #[test]
    fn preview_collapses_whitespace_and_marks_truncation() {
        let body = b"<Error>\n   <Code>ServiceUnavailable</Code>\n</Error>";
        let preview = body_preview(body);
        assert!(!preview.contains('\n'));
        assert!(preview.contains("<Code>ServiceUnavailable</Code>"));

        let long = vec![b'a'; PREVIEW_LIMIT + 10];
        assert!(body_preview(&long).ends_with(" ..."));
        assert_eq!(body_preview(&[]), "empty body");
    }

    #[test]
    fn preview_falls_back_to_hex_for_binary_bodies() {
        let preview = body_preview(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(preview.starts_with("first bytes 1f 8b"), "{}", preview);
    }

    #[tokio::test]
    async fn validates_file_on_disk_and_returns_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("code.tar.gz");
        let data = gzip_bytes(&tar_bytes());
        tokio::fs::write(&path, &data).await.unwrap();

        let size = validate_archive_file("builds/app/code.tar.gz", &path)
            .await
            .expect("archive on disk is valid");
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn rejects_error_document_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("code.tar.gz");
        tokio::fs::write(&path, S3_ERROR_BODY).await.unwrap();

        let error = validate_archive_file("builds/app/code.tar.gz", &path)
            .await
            .expect_err("error document on disk must be rejected");
        assert!(error.to_string().contains("it is an error document"));
    }
}
