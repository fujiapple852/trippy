use anyhow::Context;
use itertools::Itertools;
use maxminddb::Reader;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::rc::Rc;
use std::str::FromStr;

#[derive(Debug, Clone, Default)]
pub struct GeoIpCity {
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius: Option<u16>,
    city: Option<String>,
    subdivision: Option<String>,
    subdivision_code: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    continent: Option<String>,
}

impl GeoIpCity {
    pub fn short_name(&self) -> String {
        [
            self.city.as_ref(),
            self.subdivision_code.as_ref(),
            self.country_code.as_ref(),
        ]
        .into_iter()
        .flatten()
        .join(", ")
    }

    pub fn long_name(&self) -> String {
        [
            self.city.as_ref(),
            self.subdivision.as_ref(),
            self.country.as_ref(),
            self.continent.as_ref(),
        ]
        .into_iter()
        .flatten()
        .join(", ")
    }

    pub fn location(&self) -> String {
        format!(
            "{}, {} (~{}km)",
            self.latitude.unwrap_or_default(),
            self.longitude.unwrap_or_default(),
            self.accuracy_radius.unwrap_or_default(),
        )
    }

    pub const fn coordinates(&self) -> Option<(f64, f64, u16)> {
        match (self.latitude, self.longitude, self.accuracy_radius) {
            (Some(lat), Some(long), Some(radius)) => Some((lat, long, radius)),
            _ => None,
        }
    }
}

mod ipinfo {
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    /// The legacy `IPinfo` mmdb database format.
    ///
    /// Support both the "IP to Geolocation Extended" and "IP to Country + ASN" database formats.
    ///
    /// IP to Geolocation Extended Database:
    /// See <https://ipinfo.io/developers/ip-to-geolocation-extended/>
    ///
    /// IP to Country + ASN Database;
    /// See <https://ipinfo.io/developers/ip-to-country-asn-database/>
    #[serde_as]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct IpInfoGeoIpLegacy {
        /// "42.48948"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub latitude: Option<String>,
        /// "-83.14465"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub longitude: Option<String>,
        /// "500"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub radius: Option<String>,
        /// "Royal Oak"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub city: Option<String>,
        /// "Michigan"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub region: Option<String>,
        /// "48067"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub postal_code: Option<String>,
        /// "US"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub country: Option<String>,
        /// "Japan"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub country_name: Option<String>,
        /// "Asia"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub continent_name: Option<String>,
    }

    /// The `IPinfo` mmdb database format.
    ///
    /// Support the "Lite", "Core", "Plus" and "IP to Geolocation Database"
    /// database formats.
    ///
    /// Lite Database:
    /// See <https://ipinfo.io/developers/ipinfo-lite-database>
    ///
    /// Core Database:
    /// See <https://ipinfo.io/developers/ipinfo-core-database>
    ///
    /// Plus Database:
    /// See <https://ipinfo.io/developers/ipinfo-plus-database>
    ///
    /// IP to Geolocation Database:
    /// See <https://ipinfo.io/developers/ip-to-geolocation-database>
    #[serde_as]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct IpInfoGeoIp {
        /// 42.48948
        #[serde(default)]
        pub latitude: Option<f64>,
        /// -83.14465
        #[serde(default)]
        pub longitude: Option<f64>,
        /// 500
        #[serde(default)]
        pub radius: Option<i64>,
        /// "Royal Oak"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub city: Option<String>,
        /// "Michigan"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub region: Option<String>,
        /// "MI"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub region_code: Option<String>,
        /// "48067"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub postal_code: Option<String>,
        /// "US"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub country_code: Option<String>,
        /// "Japan"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub country: Option<String>,
        /// "Asia"
        #[serde(default)]
        #[serde_as(as = "serde_with::NoneAsEmptyString")]
        pub continent: Option<String>,
    }

    /// The `IPinfo` database format.
    ///
    /// See <https://community.ipinfo.io/t/migrating-from-ipinfo-country-asn-legacy-to-ipinfo-lite-mmdb-version/7268>
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum DatabaseFormat {
        /// The legacy `IPinfo` database format.
        Legacy,
        /// The current `IPinfo` database format.
        Current,
    }

    impl TryFrom<&str> for DatabaseFormat {
        type Error = ();

        fn try_from(database_type: &str) -> Result<Self, Self::Error> {
            let Some(database_type) = database_type.strip_prefix("ipinfo ") else {
                return Err(());
            };
            let database_name = database_type
                .strip_suffix("_sample.mmdb")
                .or_else(|| database_type.strip_suffix(".mmdb"))
                .unwrap_or(database_type);
            match database_name {
                "generic_country_free_country_asn" | "extended_location_v2" => Ok(Self::Legacy),
                _ => Ok(Self::Current),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::geoip::{Cache, GeoIpCity, GeoIpLookup};
        use maxminddb::Reader;
        use test_case::test_case;

        #[test]
        fn test_empty() {
            let json = "{}";
            let value: IpInfoGeoIpLegacy = serde_json::from_str(json).unwrap();
            assert_eq!(None, value.latitude);
            assert_eq!(None, value.longitude);
            assert_eq!(None, value.radius);
            assert_eq!(None, value.city);
            assert_eq!(None, value.region);
            assert_eq!(None, value.postal_code);
            assert_eq!(None, value.country.as_deref());
            assert_eq!(None, value.country_name.as_deref());
            assert_eq!(None, value.continent_name.as_deref());

            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
            assert_eq!(None, value.latitude);
            assert_eq!(None, value.longitude);
            assert_eq!(None, value.radius);
            assert_eq!(None, value.city);
            assert_eq!(None, value.region);
            assert_eq!(None, value.region_code);
            assert_eq!(None, value.postal_code);
            assert_eq!(None, value.country_code.as_deref());
            assert_eq!(None, value.country.as_deref());
            assert_eq!(None, value.continent.as_deref());
        }

        #[test]
        fn test_country_asn_db_format() {
            let json = r#"
                {
                    "start_ip": "40.96.54.192",
                    "end_ip": "40.96.54.255",
                    "country": "JP",
                    "country_name": "Japan",
                    "continent": "AS",
                    "continent_name": "Asia",
                    "asn": "AS8075",
                    "as_name": "Microsoft Corporation",
                    "as_domain": "microsoft.com"
                }
                "#;
            let value: IpInfoGeoIpLegacy = serde_json::from_str(json).unwrap();
            assert_eq!(None, value.latitude);
            assert_eq!(None, value.longitude);
            assert_eq!(None, value.radius);
            assert_eq!(None, value.city);
            assert_eq!(None, value.region);
            assert_eq!(None, value.postal_code);
            assert_eq!(Some("JP"), value.country.as_deref());
            assert_eq!(Some("Japan"), value.country_name.as_deref());
            assert_eq!(Some("Asia"), value.continent_name.as_deref());
        }

        #[test]
        fn test_extended_db_format() {
            let json = r#"
                {
                    "start_ip": "60.127.10.249",
                    "end_ip": "60.127.10.249",
                    "join_key": "60.127.0.0",
                    "city": "Yokohama",
                    "region": "Kanagawa",
                    "country": "JP",
                    "latitude": "35.43333",
                    "longitude": "139.65",
                    "postal_code": "220-8588",
                    "timezone": "Asia/Tokyo",
                    "geoname_id": "1848354",
                    "radius": "500"
                }
                "#;
            let value: IpInfoGeoIpLegacy = serde_json::from_str(json).unwrap();
            assert_eq!(Some("35.43333"), value.latitude.as_deref());
            assert_eq!(Some("139.65"), value.longitude.as_deref());
            assert_eq!(Some("500"), value.radius.as_deref());
            assert_eq!(Some("Yokohama"), value.city.as_deref());
            assert_eq!(Some("Kanagawa"), value.region.as_deref());
            assert_eq!(Some("220-8588"), value.postal_code.as_deref());
            assert_eq!(Some("JP"), value.country.as_deref());
            assert_eq!(None, value.country_name.as_deref());
            assert_eq!(None, value.continent_name.as_deref());
        }

        #[test]
        fn test_lite_db_format() {
            let json = r#"
                {
                  "network": "1.0.0.0/24",
                  "country": "Australia",
                  "country_code": "AU",
                  "continent": "Oceania",
                  "continent_code": "OC",
                  "asn": "AS13335",
                  "as_name": "Cloudflare, Inc.",
                  "as_domain": "cloudflare.com"
                }
                "#;
            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
            assert_eq!(None, value.latitude);
            assert_eq!(None, value.longitude);
            assert_eq!(None, value.radius);
            assert_eq!(None, value.city);
            assert_eq!(None, value.region);
            assert_eq!(None, value.postal_code);
            assert_eq!(Some("AU"), value.country_code.as_deref());
            assert_eq!(Some("Australia"), value.country.as_deref());
            assert_eq!(Some("Oceania"), value.continent.as_deref());
        }

        #[test]
        fn test_core_db_format() {
            let json = r#"
                {
                  "network": "1.0.0.0/31",
                  "city": "Sydney",
                  "region": "New South Wales",
                  "region_code": "NSW",
                  "country": "Australia",
                  "country_code": "AU",
                  "continent": "Oceania",
                  "continent_code": "OC",
                  "latitude": -33.86785,
                  "longitude": 151.20732,
                  "timezone": "Australia/Sydney",
                  "postal_code": "1001",
                  "asn": "AS13335",
                  "as_name": "Cloudflare, Inc.",
                  "as_domain": "cloudflare.com",
                  "as_type": "hosting",
                  "is_anonymous": false,
                  "is_anycast": true,
                  "is_hosting": true,
                  "is_mobile": false,
                  "is_satellite": false
                }
                "#;
            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
            assert_eq!(Some(-33.86785), value.latitude);
            assert_eq!(Some(151.20732), value.longitude);
            assert_eq!(None, value.radius);
            assert_eq!(Some("Sydney"), value.city.as_deref());
            assert_eq!(Some("New South Wales"), value.region.as_deref());
            assert_eq!(Some("NSW"), value.region_code.as_deref());
            assert_eq!(Some("1001"), value.postal_code.as_deref());
            assert_eq!(Some("AU"), value.country_code.as_deref());
            assert_eq!(Some("Australia"), value.country.as_deref());
            assert_eq!(Some("Oceania"), value.continent.as_deref());
        }

        #[test]
        fn test_plus_db_format() {
            let json = r#"
                {
                  "network": "1.0.0.0/31",
                  "city": "Sydney",
                  "region": "New South Wales",
                  "region_code": "NSW",
                  "country": "Australia",
                  "country_code": "AU",
                  "continent": "Oceania",
                  "continent_code": "OC",
                  "latitude": -33.86785,
                  "longitude": 151.20732,
                  "timezone": "Australia/Sydney",
                  "postal_code": "1001",
                  "dma_code": null,
                  "geoname_id": "2147714",
                  "radius": 5000,
                  "asn": "AS13335",
                  "as_name": "Cloudflare, Inc.",
                  "as_domain": "cloudflare.com",
                  "as_type": "hosting",
                  "carrier_name": null,
                  "mcc": null,
                  "mnc": null,
                  "as_changed": "2021-05-01",
                  "geo_changed": "2026-02-08",
                  "is_anonymous": false,
                  "is_anycast": true,
                  "is_hosting": true,
                  "is_mobile": false,
                  "is_satellite": false,
                  "is_proxy": false,
                  "is_relay": false,
                  "is_tor": false,
                  "is_vpn": false,
                  "privacy_name": null
                }
                "#;
            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
            assert_eq!(Some(-33.86785), value.latitude);
            assert_eq!(Some(151.20732), value.longitude);
            assert_eq!(Some(5000), value.radius);
            assert_eq!(Some("Sydney"), value.city.as_deref());
            assert_eq!(Some("New South Wales"), value.region.as_deref());
            assert_eq!(Some("NSW"), value.region_code.as_deref());
            assert_eq!(Some("1001"), value.postal_code.as_deref());
            assert_eq!(Some("AU"), value.country_code.as_deref());
            assert_eq!(Some("Australia"), value.country.as_deref());
            assert_eq!(Some("Oceania"), value.continent.as_deref());
        }

        macro_rules! mmdb_database_bytes {
            ($file_name:literal) => {
                include_bytes!(concat!("../tests/resources/ipinfo/", $file_name))
            };
        }

        fn geoip_lookup(bytes: &'static [u8]) -> GeoIpLookup {
            GeoIpLookup {
                reader: Some(Reader::from_source(bytes.to_vec()).unwrap()),
                cache: Cache::default(),
                locale: String::from("en"),
            }
        }

        fn lookup(geoip_lookup: &GeoIpLookup, addr: &str) -> GeoIpCity {
            geoip_lookup
                .lookup(addr.parse().unwrap())
                .unwrap()
                .unwrap()
                .as_ref()
                .clone()
        }

        #[test_case("ipinfo generic_country_free_country_asn.mmdb", Some(DatabaseFormat::Legacy); "country asn")]
        #[test_case("ipinfo generic_country_free_country_asn_sample.mmdb", Some(DatabaseFormat::Legacy); "country asn sample")]
        #[test_case("ipinfo extended_location_v2.mmdb", Some(DatabaseFormat::Legacy); "extended location")]
        #[test_case("ipinfo extended_location_v2_sample.mmdb", Some(DatabaseFormat::Legacy); "extended location sample")]
        #[test_case("ipinfo bundle_location_lite.mmdb", Some(DatabaseFormat::Current); "lite")]
        #[test_case("ipinfo bundle_location_lite_sample.mmdb", Some(DatabaseFormat::Current); "lite sample")]
        #[test_case("ipinfo bundle_location_core.mmdb", Some(DatabaseFormat::Current); "core")]
        #[test_case("ipinfo bundle_location_core_sample.mmdb", Some(DatabaseFormat::Current); "core sample")]
        #[test_case("ipinfo bundle_location_plus.mmdb", Some(DatabaseFormat::Current); "plus")]
        #[test_case("ipinfo bundle_location_plus_sample.mmdb", Some(DatabaseFormat::Current); "plus sample")]
        #[test_case("ipinfo standard_location_new.mmdb", Some(DatabaseFormat::Current); "location")]
        #[test_case("ipinfo standard_location_new_sample.mmdb", Some(DatabaseFormat::Current); "location sample")]
        #[test_case("GeoLite2-City", None; "non ipinfo")]
        fn test_ipinfo_database_format(database_type: &str, expected: Option<DatabaseFormat>) {
            assert_eq!(expected, DatabaseFormat::try_from(database_type).ok());
        }

        #[test]
        fn test_ipinfo_country_asn_sample_mmdb() {
            let geoip_lookup = geoip_lookup(mmdb_database_bytes!("ip_country_asn_sample.mmdb"));
            let geo = lookup(&geoip_lookup, "1.0.0.0");
            assert_eq!(None, geo.latitude);
            assert_eq!(None, geo.longitude);
            assert_eq!(None, geo.accuracy_radius);
            assert_eq!(None, geo.city.as_deref());
            assert_eq!(Some("Australia"), geo.country.as_deref());
            assert_eq!(Some("AU"), geo.country_code.as_deref());
            assert_eq!(Some("Oceania"), geo.continent.as_deref());
        }

        #[test]
        fn test_ipinfo_extended_location_sample_mmdb() {
            let geoip_lookup =
                geoip_lookup(mmdb_database_bytes!("ip_geolocation_extended_sample.mmdb"));
            let geo = lookup(&geoip_lookup, "1.0.0.0");
            assert_eq!(Some(-33.86785), geo.latitude);
            assert_eq!(Some(151.20732), geo.longitude);
            assert_eq!(Some(5000), geo.accuracy_radius);
            assert_eq!(Some("Sydney"), geo.city.as_deref());
            assert_eq!(Some("NSW"), geo.subdivision.as_deref());
            assert_eq!(Some("1001"), geo.subdivision_code.as_deref());
            assert_eq!(Some("Australia"), geo.country.as_deref());
            assert_eq!(Some("AU"), geo.country_code.as_deref());
            assert_eq!(None, geo.continent.as_deref());
        }

        #[test]
        fn test_ipinfo_lite_sample_mmdb() {
            let geoip_lookup = geoip_lookup(mmdb_database_bytes!("ipinfo_lite_sample.mmdb"));
            let geo = lookup(&geoip_lookup, "1.0.0.0");
            assert_eq!(None, geo.latitude);
            assert_eq!(None, geo.longitude);
            assert_eq!(None, geo.accuracy_radius);
            assert_eq!(None, geo.city.as_deref());
            assert_eq!(Some("Australia"), geo.country.as_deref());
            assert_eq!(Some("AU"), geo.country_code.as_deref());
            assert_eq!(Some("Oceania"), geo.continent.as_deref());
        }

        #[test]
        fn test_ipinfo_core_sample_mmdb() {
            let geoip_lookup = geoip_lookup(mmdb_database_bytes!("ipinfo_core_sample.mmdb"));
            let geo = lookup(&geoip_lookup, "1.0.0.0");
            assert_eq!(Some(-33.86785), geo.latitude);
            assert_eq!(Some(151.20732), geo.longitude);
            assert_eq!(None, geo.accuracy_radius);
            assert_eq!(Some("Sydney"), geo.city.as_deref());
            assert_eq!(Some("New South Wales"), geo.subdivision.as_deref());
            assert_eq!(Some("NSW"), geo.subdivision_code.as_deref());
            assert_eq!(Some("Australia"), geo.country.as_deref());
            assert_eq!(Some("AU"), geo.country_code.as_deref());
            assert_eq!(Some("Oceania"), geo.continent.as_deref());
        }

        #[test]
        fn test_ipinfo_plus_sample_mmdb() {
            let geoip_lookup = geoip_lookup(mmdb_database_bytes!("ipinfo_plus_sample.mmdb"));
            let geo = lookup(&geoip_lookup, "1.0.0.0");
            assert_eq!(Some(-33.86785), geo.latitude);
            assert_eq!(Some(151.20732), geo.longitude);
            assert_eq!(Some(5000), geo.accuracy_radius);
            assert_eq!(Some("Sydney"), geo.city.as_deref());
            assert_eq!(Some("New South Wales"), geo.subdivision.as_deref());
            assert_eq!(Some("NSW"), geo.subdivision_code.as_deref());
            assert_eq!(Some("Australia"), geo.country.as_deref());
            assert_eq!(Some("AU"), geo.country_code.as_deref());
            assert_eq!(Some("Oceania"), geo.continent.as_deref());
        }

        #[test]
        fn test_ipinfo_location_sample_mmdb() {
            let geoip_lookup = geoip_lookup(mmdb_database_bytes!("ipinfo_location_sample.mmdb"));
            let geo = lookup(&geoip_lookup, "1.0.0.0");
            assert_eq!(Some(-33.86785), geo.latitude);
            assert_eq!(Some(151.20732), geo.longitude);
            assert_eq!(None, geo.accuracy_radius);
            assert_eq!(Some("Sydney"), geo.city.as_deref());
            assert_eq!(Some("New South Wales"), geo.subdivision.as_deref());
            assert_eq!(Some("NSW"), geo.subdivision_code.as_deref());
            assert_eq!(Some("Australia"), geo.country.as_deref());
            assert_eq!(Some("AU"), geo.country_code.as_deref());
            assert_eq!(Some("Oceania"), geo.continent.as_deref());
        }
    }
}

impl From<ipinfo::IpInfoGeoIpLegacy> for GeoIpCity {
    fn from(value: ipinfo::IpInfoGeoIpLegacy) -> Self {
        Self {
            latitude: value.latitude.and_then(|val| f64::from_str(&val).ok()),
            longitude: value.longitude.and_then(|val| f64::from_str(&val).ok()),
            accuracy_radius: value.radius.and_then(|val| u16::from_str(&val).ok()),
            city: value.city,
            subdivision: value.region,
            subdivision_code: value.postal_code,
            country: value.country_name,
            country_code: value.country,
            continent: value.continent_name,
        }
    }
}

impl From<ipinfo::IpInfoGeoIp> for GeoIpCity {
    fn from(value: ipinfo::IpInfoGeoIp) -> Self {
        Self {
            latitude: value.latitude,
            longitude: value.longitude,
            accuracy_radius: value.radius.and_then(|radius| u16::try_from(radius).ok()),
            city: value.city,
            subdivision: value.region,
            subdivision_code: value.region_code,
            country: value.country,
            country_code: value.country_code,
            continent: value.continent,
        }
    }
}

impl From<(maxminddb::geoip2::City<'_>, &str)> for GeoIpCity {
    fn from((value, locale): (maxminddb::geoip2::City<'_>, &str)) -> Self {
        let city = localized_name(&value.city.names, locale);
        let subdivision = value
            .subdivisions
            .first()
            .and_then(|c| localized_name(&c.names, locale));
        let subdivision_code = value
            .subdivisions
            .first()
            .and_then(|c| c.iso_code.as_ref().map(ToString::to_string));
        let country = localized_name(&value.country.names, locale);
        let country_code = value.country.iso_code.map(ToString::to_string);
        let continent = localized_name(&value.continent.names, locale);
        let latitude = value.location.latitude;
        let longitude = value.location.longitude;
        let accuracy_radius = value.location.accuracy_radius;
        Self {
            latitude,
            longitude,
            accuracy_radius,
            city,
            subdivision,
            subdivision_code,
            country,
            country_code,
            continent,
        }
    }
}

/// The fallback locale.
///
/// The `MaxMind` support documentation says:
///
/// > Our geolocation name data includes the names of the continent, country, city, and
/// > subdivisions of the location of the IP address. We include the country names in
/// > English, Simplified Chinese, Spanish, Brazilian Portuguese, Russian, Japanese, French,
/// > and German.
/// >
/// > Please note: Not every place name is always available in each language. We recommend checking
/// > English names as a default for cases where a localized name is not available in your preferred
/// > language.
const FALLBACK_LOCALE: &str = "en";

/// Alias for a cache of `GeoIp` data.
type Cache = RefCell<HashMap<IpAddr, Option<Rc<GeoIpCity>>>>;

/// Lookup `GeoIpCity` data form an `IpAddr`.
#[derive(Debug)]
pub struct GeoIpLookup {
    reader: Option<Reader<Vec<u8>>>,
    cache: Cache,
    locale: String,
}

impl GeoIpLookup {
    /// Create a new `GeoIpLookup` from a `MaxMind` DB file.
    pub fn from_file<P: AsRef<Path>>(path: P, locale: String) -> anyhow::Result<Self> {
        let reader =
            Reader::open_readfile(path.as_ref()).context(format!("{}", path.as_ref().display()))?;
        Ok(Self {
            reader: Some(reader),
            cache: RefCell::new(HashMap::new()),
            locale,
        })
    }

    /// Create a `GeoIpLookup` that returns `None` for all `IpAddr` lookups.
    pub fn empty() -> Self {
        Self {
            reader: None,
            cache: RefCell::new(HashMap::new()),
            locale: FALLBACK_LOCALE.to_string(),
        }
    }

    /// Lookup an `GeoIpCity` for an `IpAddr`.
    ///
    /// If an entry is found it is cached and returned, otherwise None is returned.
    pub fn lookup(&self, addr: IpAddr) -> anyhow::Result<Option<Rc<GeoIpCity>>> {
        if let Some(reader) = &self.reader {
            if let Some(geo) = self.cache.borrow().get(&addr) {
                return Ok(geo.clone());
            }
            let lookup_result = reader.lookup(addr)?;
            let city_data =
                match ipinfo::DatabaseFormat::try_from(reader.metadata.database_type.as_ref()).ok()
                {
                    Some(ipinfo::DatabaseFormat::Legacy) => lookup_result
                        .decode::<ipinfo::IpInfoGeoIpLegacy>()?
                        .map(GeoIpCity::from),
                    Some(ipinfo::DatabaseFormat::Current) => lookup_result
                        .decode::<ipinfo::IpInfoGeoIp>()?
                        .map(GeoIpCity::from),
                    None => lookup_result
                        .decode::<maxminddb::geoip2::City<'_>>()?
                        .map(|city| GeoIpCity::from((city, self.locale.as_ref()))),
                };
            let cached = city_data.map(Rc::new);
            self.cache.borrow_mut().insert(addr, cached.clone());
            Ok(cached)
        } else {
            Ok(None)
        }
    }
}

fn localized_name(names: &maxminddb::geoip2::Names<'_>, locale: &str) -> Option<String> {
    lookup_locale(names, locale)
        .or_else(|| lookup_locale(names, FALLBACK_LOCALE))
        .map(ToString::to_string)
}

/// Map a Trippy locale code to the closest `maxminddb` locale field.
///
/// - `pt*` (e.g. `pt`, `pt-BR`, `pt-PT`) use `brazilian_portuguese`
/// - `zh*` (e.g. `zh`, `zh-TW`) use `simplified_chinese`
/// - Other languages that are supported map directly (`en`, `de`, `es`, `fr`, `ja`, `ru`).
fn lookup_locale<'a>(names: &maxminddb::geoip2::Names<'a>, code: &str) -> Option<&'a str> {
    if code.starts_with("pt") {
        names.brazilian_portuguese
    } else if code.starts_with("zh") {
        names.simplified_chinese
    } else {
        match code {
            "de" => names.german,
            "en" => names.english,
            "es" => names.spanish,
            "fr" => names.french,
            "ja" => names.japanese,
            "ru" => names.russian,
            _ => None,
        }
    }
}
