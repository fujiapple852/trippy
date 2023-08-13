use anyhow::Context;
use itertools::Itertools;
use maxminddb::geoip2::City;
use maxminddb::Reader;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::rc::Rc;

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

    pub fn coordinates(&self) -> Option<(f64, f64, u16)> {
        match (self.latitude, self.longitude, self.accuracy_radius) {
            (Some(lat), Some(long), Some(raduis)) => Some((lat, long, raduis)),
            _ => None,
        }
    }
}

impl From<City<'_>> for GeoIpCity {
    fn from(value: City<'_>) -> Self {
        let city = value
            .city
            .as_ref()
            .and_then(|city| city.names.as_ref())
            .and_then(|names| names.get(LOCALE))
            .map(ToString::to_string);
        let subdivision = value
            .subdivisions
            .as_ref()
            .and_then(|c| c.first())
            .and_then(|c| c.names.as_ref())
            .and_then(|names| names.get(LOCALE))
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
            .and_then(|names| names.get(LOCALE))
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
            .and_then(|names| names.get(LOCALE))
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

/// The default locale.
const LOCALE: &str = "en";

/// Alias for a cache of `GeoIp` data.
type Cache = RefCell<HashMap<IpAddr, Rc<GeoIpCity>>>;

/// Lookup `GeoIpCity` data form an `IpAddr`.
#[derive(Debug)]
pub struct GeoIpLookup {
    reader: Option<Reader<Vec<u8>>>,
    cache: Cache,
}

impl GeoIpLookup {
    /// Create a new `GeoIpLookup` from a `MaxMind` DB file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path.as_ref())
            .context(format!("{}", path.as_ref().display()))?;
        Ok(Self {
            reader: Some(reader),
            cache: RefCell::new(HashMap::new()),
        })
    }

    /// Create a `GeoIpLookup` that returns `None` for all `IpAddr` lookups.
    pub fn empty() -> Self {
        Self {
            reader: None,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Lookup an `GeoIpCity` for an `IpAddr`.
    ///
    /// If an entry is found it is cached and returned, otherwise None is returned.
    pub fn lookup(&self, addr: IpAddr) -> anyhow::Result<Option<Rc<GeoIpCity>>> {
        if let Some(reader) = &self.reader {
            if let Some(geo) = self.cache.borrow().get(&addr).map(Clone::clone) {
                return Ok(Some(geo));
            }
            let city_data = reader.lookup::<City<'_>>(addr)?;
            let geo = self
                .cache
                .borrow_mut()
                .insert(addr, Rc::new(GeoIpCity::from(city_data)));
            Ok(geo)
        } else {
            Ok(None)
        }
    }
}
