// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scheduled GeoLite2 refresh.
//!
//! MaxMind's terms require the database to be refreshed at least every 30 days. This job
//! refreshes after [`REFRESH_AFTER`] (7 days) so a failed attempt still leaves a margin, and
//! reports [`is_overdue`] once the file passes [`MAX_DB_AGE`].
//!
//! Safety properties:
//! * The license key is only ever placed in the download URL. Errors are reduced to status
//!   codes or transport kinds, so the key cannot leak through an error message.
//! * The archive is fully validated (it must contain an `.mmdb` whose metadata names the
//!   requested edition) before anything on disk changes.
//! * Replacement is atomic (temp file + rename). A failed refresh keeps the last good database.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::Fetcher;

pub const EDITION_CITY: &str = "GeoLite2-City";
pub const EDITION_ASN: &str = "GeoLite2-ASN";
/// Refresh once the local copy is this old.
pub const REFRESH_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// MaxMind's maximum age for an in-use copy.
pub const MAX_DB_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Largest archive or extracted database accepted (GeoLite2 is well under this).
pub const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
const DOWNLOAD_BASE: &str = "https://download.maxmind.com/app/geoip_download";

/// Build the download URL for an edition. Contains the license key: never log it.
pub fn download_url(edition: &str, license_key: &str) -> Result<String, String> {
    check_edition(edition)?;
    if license_key.is_empty()
        || !license_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("malformed license key".into());
    }
    Ok(format!(
        "{DOWNLOAD_BASE}?edition_id={edition}&license_key={license_key}&suffix=tar.gz"
    ))
}

fn check_edition(edition: &str) -> Result<(), String> {
    match edition {
        EDITION_CITY | EDITION_ASN => Ok(()),
        other => Err(format!("unsupported edition: {other}")),
    }
}

/// True when the local copy should be refreshed. A missing copy is always due.
pub fn is_due(age: Option<Duration>) -> bool {
    age.is_none_or(|a| a >= REFRESH_AFTER)
}

/// True when the local copy is older than MaxMind allows.
pub fn is_overdue(age: Option<Duration>) -> bool {
    age.is_some_and(|a| a > MAX_DB_AGE)
}

/// Age of a database file, from its modification time.
pub fn file_age(path: &Path, now: SystemTime) -> Option<Duration> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    now.duration_since(modified).ok()
}

/// Extract the single `.mmdb` file from a `tar.gz` archive, bounded in size.
pub fn extract_mmdb(archive_gz: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = flate2::read::GzDecoder::new(archive_gz);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|_| "archive is not a valid tar.gz")?;
    for entry in entries {
        let entry = entry.map_err(|_| "archive entry is unreadable")?;
        let is_mmdb = entry
            .path()
            .map(|p| p.to_string_lossy().ends_with(".mmdb"))
            .unwrap_or(false);
        if !is_mmdb {
            continue;
        }
        let mut out = Vec::new();
        entry
            .take(MAX_DOWNLOAD_BYTES + 1)
            .read_to_end(&mut out)
            .map_err(|_| "cannot read database from archive")?;
        if out.len() as u64 > MAX_DOWNLOAD_BYTES {
            return Err("database exceeds size limit".into());
        }
        return Ok(out);
    }
    Err("archive contains no .mmdb file".into())
}

/// What a successful refresh produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Updated {
    pub path: PathBuf,
    pub bytes: u64,
}

/// Download, validate and atomically install one edition. `validate` receives the extracted
/// database and must reject anything that is not the expected edition.
pub fn update_database(
    fetcher: &dyn Fetcher,
    edition: &str,
    license_key: &str,
    dest: &Path,
    validate: impl Fn(&[u8]) -> Result<(), String>,
) -> Result<Updated, String> {
    let url = download_url(edition, license_key)?;
    let archive = fetcher.fetch(&url)?;
    let mmdb = extract_mmdb(&archive)?;
    validate(&mmdb)?;

    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create directory: {e}"))?;
    }
    let tmp = dest.with_extension("mmdb.tmp");
    std::fs::write(&tmp, &mmdb).map_err(|e| format!("cannot write database: {e}"))?;
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot install database: {e}")
    })?;
    Ok(Updated {
        path: dest.to_path_buf(),
        bytes: mmdb.len() as u64,
    })
}

/// Validator for production use: the database must open and name the expected edition.
pub fn validator_for(edition: &'static str) -> impl Fn(&[u8]) -> Result<(), String> {
    move |bytes: &[u8]| {
        let reader = maxminddb::Reader::from_source(bytes.to_vec())
            .map_err(|_| "downloaded file is not a valid MaxMind database".to_string())?;
        if reader.metadata().database_type.contains(edition) {
            Ok(())
        } else {
            Err(format!(
                "downloaded database is {}, expected {edition}",
                reader.metadata().database_type
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Build a tar.gz containing the given (path, bytes) entries.
    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    struct FakeFetcher {
        result: Result<Vec<u8>, String>,
        urls: RefCell<Vec<String>>,
    }

    impl Fetcher for FakeFetcher {
        fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
            self.urls.borrow_mut().push(url.to_string());
            self.result.clone()
        }
    }

    fn fake(result: Result<Vec<u8>, String>) -> FakeFetcher {
        FakeFetcher {
            result,
            urls: RefCell::new(Vec::new()),
        }
    }

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("tpt-netguard-update-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn url_is_built_for_known_editions_only() {
        let url = download_url(EDITION_CITY, "KEY_123").unwrap();
        assert!(url.starts_with("https://download.maxmind.com/"));
        assert!(url.contains("edition_id=GeoLite2-City"));
        assert!(download_url("GeoIP2-Secret", "KEY_123").is_err());
        assert!(download_url(EDITION_ASN, "bad key!").is_err());
    }

    #[test]
    fn due_and_overdue_thresholds() {
        assert!(is_due(None));
        assert!(!is_due(Some(Duration::from_secs(3600))));
        assert!(is_due(Some(REFRESH_AFTER)));
        assert!(!is_overdue(Some(REFRESH_AFTER)));
        assert!(is_overdue(Some(MAX_DB_AGE + Duration::from_secs(1))));
        assert!(!is_overdue(None));
    }

    #[test]
    fn extracts_mmdb_and_ignores_other_entries() {
        let gz = archive(&[
            ("GeoLite2-City_20260101/README.txt", b"readme"),
            ("GeoLite2-City_20260101/GeoLite2-City.mmdb", b"DBBYTES"),
            ("GeoLite2-City_20260101/LICENSE.txt", b"license"),
        ]);
        assert_eq!(extract_mmdb(&gz).unwrap(), b"DBBYTES");
    }

    #[test]
    fn archive_without_database_is_rejected() {
        let gz = archive(&[("readme.txt", b"no db here")]);
        assert!(extract_mmdb(&gz).is_err());
        assert!(extract_mmdb(b"not gzip at all").is_err());
    }

    #[test]
    fn successful_update_installs_database_atomically() {
        let d = dir("ok");
        let dest = d.join("GeoLite2-City.mmdb");
        let f = fake(Ok(archive(&[("x/GeoLite2-City.mmdb", b"NEWDB")])));
        let updated = update_database(&f, EDITION_CITY, "KEY_123", &dest, |_| Ok(())).unwrap();
        assert_eq!(updated.bytes, 5);
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEWDB");
        assert!(!dest.with_extension("mmdb.tmp").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_download_keeps_last_good_database() {
        let d = dir("fetchfail");
        std::fs::create_dir_all(&d).unwrap();
        let dest = d.join("GeoLite2-City.mmdb");
        std::fs::write(&dest, b"GOODDB").unwrap();
        let f = fake(Err("HTTP 401".into()));
        let err = update_database(&f, EDITION_CITY, "KEY_123", &dest, |_| Ok(())).unwrap_err();
        assert_eq!(err, "HTTP 401");
        assert_eq!(std::fs::read(&dest).unwrap(), b"GOODDB");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_validation_keeps_last_good_database() {
        let d = dir("validate");
        std::fs::create_dir_all(&d).unwrap();
        let dest = d.join("GeoLite2-City.mmdb");
        std::fs::write(&dest, b"GOODDB").unwrap();
        let f = fake(Ok(archive(&[("x/GeoLite2-ASN.mmdb", b"WRONG")])));
        let err = update_database(&f, EDITION_CITY, "KEY_123", &dest, |_| {
            Err("expected GeoLite2-City".into())
        })
        .unwrap_err();
        assert!(err.contains("expected"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"GOODDB");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn errors_never_contain_the_license_key() {
        let d = dir("nokey");
        let f = fake(Err("transport: io".into()));
        let err = update_database(&f, EDITION_CITY, "SECRETKEY99", &d.join("x.mmdb"), |_| {
            Ok(())
        })
        .unwrap_err();
        assert!(!err.contains("SECRETKEY99"));
        // The key is only used in the request URL.
        assert!(f.urls.borrow()[0].contains("SECRETKEY99"));
    }
}
