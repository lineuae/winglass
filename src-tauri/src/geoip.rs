//! IP → ISO-3166 country code resolution via a bundled MaxMind-format
//! database. We ship the db-ip.com Lite MMDB alongside the executable
//! (`resources/GeoLite2-Country.mmdb`); the installer places it in the
//! app directory and Tauri's resource_dir points at it.
//!
//! If the file is missing (dev build without the download, or a broken
//! install), we silently disable the feature — every lookup returns
//! None and the country column in the UI stays empty.

use std::net::IpAddr;
use std::path::Path;

pub struct GeoIp {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(serde::Deserialize)]
struct CountryRecord {
    country: Option<Country>,
}

#[derive(serde::Deserialize)]
struct Country {
    iso_code: Option<String>,
}

impl GeoIp {
    pub fn open(path: &Path) -> Self {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| {
                eprintln!("[winglass] GeoIP database not loaded ({}): {}", path.display(), e);
                e
            })
            .ok();
        Self { reader }
    }

    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let record: CountryRecord = reader.lookup(ip).ok()?;
        record.country?.iso_code
    }
}
