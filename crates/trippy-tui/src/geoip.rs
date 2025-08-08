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

    /// The `IPinfo` mmdb database format.
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
    pub struct IpInfoGeoIp {
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_empty() {
            let json = "{}";
            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
            assert_eq!(None, value.latitude);
            assert_eq!(None, value.longitude);
            assert_eq!(None, value.radius);
            assert_eq!(None, value.city);
            assert_eq!(None, value.region);
            assert_eq!(None, value.postal_code);
            assert_eq!(None, value.country.as_deref());
            assert_eq!(None, value.country_name.as_deref());
            assert_eq!(None, value.continent_name.as_deref());
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
            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
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
            let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
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
    }
}

impl From<ipinfo::IpInfoGeoIp> for GeoIpCity {
    fn from(value: ipinfo::IpInfoGeoIp) -> Self {
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

impl From<(maxminddb::geoip2::City<'_>, &str)> for GeoIpCity {
    fn from((value, locale): (maxminddb::geoip2::City<'_>, &str)) -> Self {
        let city = value
            .city
            .as_ref()
            .and_then(|city| city.names.as_ref())
            .and_then(|names| names.get(locale).or_else(|| names.get(FALLBACK_LOCALE)))
            .map(ToString::to_string);
        let subdivision = value
            .subdivisions
            .as_ref()
            .and_then(|c| c.first())
            .and_then(|c| c.names.as_ref())
            .and_then(|names| names.get(locale).or_else(|| names.get(FALLBACK_LOCALE)))
            .map(ToString::to_string);
        let subdivision_code = value
            .subdivisions
            .as_ref()
            .and_then(|c| c.first())
            .and_then(|c| c.iso_code.as_ref())
            .map(ToString::to_string);
        let country = value
            .country
            .as_ref()
            .and_then(|country| country.names.as_ref())
            .and_then(|names| names.get(locale).or_else(|| names.get(FALLBACK_LOCALE)))
            .map(ToString::to_string);
        let country_code = value
            .country
            .as_ref()
            .and_then(|country| country.iso_code.as_ref())
            .map(ToString::to_string);
        let continent = value
            .continent
            .as_ref()
            .and_then(|continent| continent.names.as_ref())
            .and_then(|names| names.get(locale).or_else(|| names.get(FALLBACK_LOCALE)))
            .map(ToString::to_string);
        let latitude = value
            .location
            .as_ref()
            .and_then(|location| location.latitude);
        let longitude = value
            .location
            .as_ref()
            .and_then(|location| location.longitude);
        let accuracy_radius = value
            .location
            .as_ref()
            .and_then(|location| location.accuracy_radius);
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
        let reader = maxminddb::Reader::open_readfile(path.as_ref())
            .context(format!("{}", path.as_ref().display()))?;
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
            let city_data = if reader.metadata.database_type.starts_with("ipinfo") {
                reader
                    .lookup::<ipinfo::IpInfoGeoIp>(addr)?
                    .map(GeoIpCity::from)
            } else {
                reader
                    .lookup::<maxminddb::geoip2::City<'_>>(addr)?
                    .map(|city| GeoIpCity::from((city, self.locale.as_ref())))
            };
            let cached = city_data.map(Rc::new);
            self.cache.borrow_mut().insert(addr, cached.clone());
            Ok(cached)
        } else {
            Ok(None)
        }
    }
}
