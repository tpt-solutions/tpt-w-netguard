// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline geo-IP for the connection map. Uses a local GeoLite2-City database only: no
//! per-connection lookups leave the machine.
//!
//! If no database is configured, or it fails to load, geo-IP is `Disabled` and the rest of
//! the app keeps working; the Map tab is simply unavailable.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use maxminddb::{geoip2, Reader};

pub mod update;

/// Downloads a URL body. Implementations must not include the URL (which may carry a license
/// key) in their error text.
pub trait Fetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// Blocking HTTPS fetcher with a timeout and a size cap.
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl HttpFetcher {
    pub fn new(timeout: Duration) -> Self {
        Self {
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
        }
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        let response = self.agent.get(url).call().map_err(|e| match e {
            // Status codes are safe to report; transport messages can echo the URL, so they are not.
            ureq::Error::Status(code, _) => format!("HTTP {code}"),
            ureq::Error::Transport(t) => format!("transport error: {:?}", t.kind()),
        })?;
        let mut body = Vec::new();
        response
            .into_reader()
            .take(update::MAX_DOWNLOAD_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("read error: {}", e.kind()))?;
        if body.len() as u64 > update::MAX_DOWNLOAD_BYTES {
            return Err("download exceeds size limit".into());
        }
        Ok(body)
    }
}

/// Autonomous system (ASN and organisation) for an address, from GeoLite2-ASN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub number: u32,
    pub organization: Option<String>,
}

/// File name of the ASN edition, expected in the same folder as the City database.
pub const ASN_FILE_NAME: &str = "GeoLite2-ASN.mmdb";

/// Where the ASN database lives, given the City database path: the same folder.
pub fn asn_path_beside(city_path: &Path) -> Option<PathBuf> {
    Some(city_path.parent()?.join(ASN_FILE_NAME))
}

/// A short owner label for an address, such as `AS15169 Google LLC` (or `AS15169` when the
/// organisation is not named in the database).
pub fn owner_label(info: &AsnInfo) -> String {
    match &info.organization {
        Some(org) => format!("AS{} {org}", info.number),
        None => format!("AS{}", info.number),
    }
}

pub struct AsnDb {
    reader: Reader<Vec<u8>>,
}

impl AsnDb {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let reader =
            Reader::from_source(bytes).map_err(|e| format!("invalid MaxMind database: {e}"))?;
        Ok(Self { reader })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        let asn: geoip2::Asn = self.reader.lookup(ip).ok()?.decode().ok()??;
        Some(AsnInfo {
            number: asn.autonomous_system_number?,
            organization: asn.autonomous_system_organization.map(String::from),
        })
    }
}

/// Location of one remote endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

pub enum GeoIp {
    Disabled { reason: String },
    Loaded { reader: Reader<Vec<u8>> },
}

impl GeoIp {
    /// Load a GeoLite2-City `.mmdb`. `None` or a missing/corrupt file yields `Disabled`
    /// rather than an error, so callers degrade gracefully.
    pub fn load(path: Option<&Path>) -> GeoIp {
        let Some(path) = path else {
            return GeoIp::Disabled {
                reason: "no GeoLite2 database configured".into(),
            };
        };
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return GeoIp::Disabled {
                    reason: format!("cannot read {}: {e}", path.display()),
                }
            }
        };
        match Reader::from_source(bytes) {
            Ok(reader) => GeoIp::Loaded { reader },
            Err(e) => GeoIp::Disabled {
                reason: format!("invalid MaxMind database: {e}"),
            },
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, GeoIp::Loaded { .. })
    }

    /// Why geo-IP is unavailable, if it is.
    pub fn disabled_reason(&self) -> Option<&str> {
        match self {
            GeoIp::Disabled { reason } => Some(reason),
            GeoIp::Loaded { .. } => None,
        }
    }

    /// Look up an address. `None` when disabled or the address is not in the database
    /// (private ranges are never in GeoLite2).
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        let GeoIp::Loaded { reader } = self else {
            return None;
        };
        let city: geoip2::City = reader.lookup(ip).ok()?.decode().ok()??;
        Some(GeoLocation {
            country: city.country.iso_code.map(String::from),
            city: city.city.names.english.map(String::from),
            latitude: city.location.latitude,
            longitude: city.location.longitude,
        })
    }
}

/// One remote connection to be placed on the map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapPoint {
    pub remote: IpAddr,
    pub bytes: u64,
}

/// Connections grouped by location, for the Map tab.
#[derive(Debug, Clone, PartialEq)]
pub struct MapCell {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub connections: usize,
    pub bytes: u64,
}

/// Group points by (country, city). Points without a location are dropped: they cannot be
/// drawn. `lookup` is injected so aggregation can be tested without a database.
pub fn aggregate_map<F>(points: &[MapPoint], lookup: F) -> Vec<MapCell>
where
    F: Fn(IpAddr) -> Option<GeoLocation>,
{
    let mut cells: BTreeMap<(Option<String>, Option<String>), MapCell> = BTreeMap::new();
    for point in points {
        let Some(loc) = lookup(point.remote) else {
            continue;
        };
        let (Some(latitude), Some(longitude)) = (loc.latitude, loc.longitude) else {
            continue;
        };
        let cell = cells
            .entry((loc.country.clone(), loc.city.clone()))
            .or_insert_with(|| MapCell {
                country: loc.country.clone(),
                city: loc.city.clone(),
                latitude,
                longitude,
                connections: 0,
                bytes: 0,
            });
        cell.connections += 1;
        cell.bytes = cell.bytes.saturating_add(point.bytes);
    }
    cells.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_database_degrades_to_disabled() {
        let geo = GeoIp::load(None);
        assert!(!geo.is_available());
        assert!(geo.lookup("8.8.8.8".parse().unwrap()).is_none());

        let geo = GeoIp::load(Some(Path::new("does/not/exist.mmdb")));
        assert!(!geo.is_available());
        assert!(geo.disabled_reason().unwrap().contains("cannot read"));
    }

    #[test]
    fn corrupt_database_degrades_to_disabled() {
        let dir = std::env::temp_dir().join("tpt-netguard-geoip-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.mmdb");
        std::fs::write(&path, b"not a maxmind database").unwrap();
        let geo = GeoIp::load(Some(&path));
        assert!(!geo.is_available());
        assert!(geo.disabled_reason().unwrap().contains("invalid MaxMind"));
        let _ = std::fs::remove_file(&path);
    }

    fn fake_lookup(ip: IpAddr) -> Option<GeoLocation> {
        match ip.to_string().as_str() {
            "1.1.1.1" | "1.0.0.1" => Some(GeoLocation {
                country: Some("AU".into()),
                city: Some("Sydney".into()),
                latitude: Some(-33.8),
                longitude: Some(151.2),
            }),
            "8.8.8.8" => Some(GeoLocation {
                country: Some("US".into()),
                city: None,
                latitude: Some(37.7),
                longitude: Some(-122.4),
            }),
            "10.0.0.5" => Some(GeoLocation {
                country: None,
                city: None,
                latitude: None,
                longitude: None,
            }),
            _ => None,
        }
    }

    #[test]
    fn aggregates_points_by_location() {
        let points = [
            MapPoint {
                remote: "1.1.1.1".parse().unwrap(),
                bytes: 100,
            },
            MapPoint {
                remote: "1.0.0.1".parse().unwrap(),
                bytes: 50,
            },
            MapPoint {
                remote: "8.8.8.8".parse().unwrap(),
                bytes: 10,
            },
            MapPoint {
                remote: "10.0.0.5".parse().unwrap(),
                bytes: 999,
            },
            MapPoint {
                remote: "203.0.113.9".parse().unwrap(),
                bytes: 999,
            },
        ];
        let cells = aggregate_map(&points, fake_lookup);
        assert_eq!(cells.len(), 2);
        let sydney = cells
            .iter()
            .find(|c| c.country.as_deref() == Some("AU"))
            .unwrap();
        assert_eq!(sydney.connections, 2);
        assert_eq!(sydney.bytes, 150);
    }
}

#[cfg(test)]
mod asn_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn asn_database_is_expected_beside_the_city_database() {
        let city = Path::new("/data/geo/GeoLite2-City.mmdb");
        assert_eq!(
            asn_path_beside(city),
            Some(PathBuf::from("/data/geo/GeoLite2-ASN.mmdb"))
        );
        assert_eq!(asn_path_beside(Path::new("")), None);
    }

    #[test]
    fn owner_labels_name_the_network_and_fall_back_to_the_number() {
        let named = AsnInfo {
            number: 15169,
            organization: Some("Google LLC".into()),
        };
        let unnamed = AsnInfo {
            number: 64500,
            organization: None,
        };
        assert_eq!(owner_label(&named), "AS15169 Google LLC");
        assert_eq!(owner_label(&unnamed), "AS64500");
    }
}
