use chrono::Utc;
use itertools::Itertools;
use serde::{Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use trippy_core::NatStatus;
use trippy_dns::Resolver;

#[derive(Serialize)]
pub struct Report {
    pub info: Info,
    pub hops: Vec<Hop>,
}

#[derive(Serialize)]
pub struct Info {
    pub target: Host,
    pub start_timestamp: chrono::DateTime<Utc>,
    pub end_timestamp: chrono::DateTime<Utc>,
}

#[derive(Serialize)]
pub struct Hop {
    pub ttl: u8,
    pub hosts: Hosts,
    pub extensions: Extensions,
    #[serde(serialize_with = "fixed_width")]
    pub loss_pct: f64,
    pub sent: usize,
    #[serde(serialize_with = "fixed_width")]
    pub last: f64,
    pub recv: usize,
    #[serde(serialize_with = "fixed_width")]
    pub avg: f64,
    #[serde(serialize_with = "fixed_width")]
    pub best: f64,
    #[serde(serialize_with = "fixed_width")]
    pub worst: f64,
    #[serde(serialize_with = "fixed_width")]
    pub stddev: f64,
    #[serde(serialize_with = "fixed_width")]
    pub jitter: f64,
    #[serde(serialize_with = "fixed_width")]
    pub javg: f64,
    #[serde(serialize_with = "fixed_width")]
    pub jmax: f64,
    #[serde(serialize_with = "fixed_width")]
    pub jinta: f64,
    pub nat: Option<bool>,
    pub tos: u8,
}

impl<R: Resolver> From<(&trippy_core::Hop, &R)> for Hop {
    fn from((value, resolver): (&trippy_core::Hop, &R)) -> Self {
        let hosts = Hosts::from((value.addrs(), resolver));
        let extensions = value.extensions().map(Extensions::from).unwrap_or_default();
        Self {
            ttl: value.ttl(),
            hosts,
            extensions,
            loss_pct: value.loss_pct(),
            sent: value.total_sent(),
            last: value.last_ms().unwrap_or_default(),
            recv: value.total_recv(),
            avg: value.avg_ms(),
            best: value.best_ms().unwrap_or_default(),
            worst: value.worst_ms().unwrap_or_default(),
            stddev: value.stddev_ms(),
            jitter: value.jitter_ms().unwrap_or_default(),
            javg: value.javg_ms(),
            jmax: value.jmax_ms().unwrap_or_default(),
            jinta: value.jinta(),
            nat: match value.last_nat_status() {
                NatStatus::NotApplicable => None,
                NatStatus::NotDetected => Some(false),
                NatStatus::Detected => Some(true),
            },
            tos: value.tos().unwrap_or_default().0,
        }
    }
}

#[derive(Serialize)]
pub struct Hosts(pub Vec<Host>);

impl<'a, R: Resolver, I: Iterator<Item = &'a IpAddr>> From<(I, &R)> for Hosts {
    fn from((value, resolver): (I, &R)) -> Self {
        Self(
            value
                .map(|ip| Host {
                    ip: *ip,
                    hostname: resolver.reverse_lookup(*ip).to_string(),
                })
                .collect(),
        )
    }
}

impl Display for Hosts {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.iter().format(", "))
    }
}

#[derive(Serialize)]
pub struct Host {
    pub ip: IpAddr,
    pub hostname: String,
}

impl Display for Host {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip)
    }
}

#[derive(Default, Serialize)]
#[serde(transparent)]
pub struct Extensions {
    pub extensions: Vec<Extension>,
}

impl From<&trippy_core::Extensions> for Extensions {
    fn from(value: &trippy_core::Extensions) -> Self {
        Self {
            extensions: value
                .extensions
                .iter()
                .cloned()
                .map(Extension::from)
                .collect(),
        }
    }
}

impl Display for Extensions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.extensions.iter().format(" + "))
    }
}

#[derive(Serialize)]
pub enum Extension {
    #[serde(rename = "unknown")]
    Unknown(UnknownExtension),
    #[serde(rename = "mpls")]
    Mpls(MplsLabelStack),
}

impl From<trippy_core::Extension> for Extension {
    fn from(value: trippy_core::Extension) -> Self {
        match value {
            trippy_core::Extension::Unknown(unknown) => {
                Self::Unknown(UnknownExtension::from(unknown))
            }
            trippy_core::Extension::Mpls(mpls) => Self::Mpls(MplsLabelStack::from(mpls)),
        }
    }
}

impl Display for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(unknown) => unknown.fmt(f),
            Self::Mpls(mpls) => mpls.fmt(f),
        }
    }
}

#[derive(Serialize)]
pub struct MplsLabelStack {
    pub members: Vec<MplsLabelStackMember>,
}

impl From<trippy_core::MplsLabelStack> for MplsLabelStack {
    fn from(value: trippy_core::MplsLabelStack) -> Self {
        Self {
            members: value
                .members
                .into_iter()
                .map(MplsLabelStackMember::from)
                .collect(),
        }
    }
}

impl Display for MplsLabelStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "mpls(labels={})", self.members.iter().format(", "))
    }
}

#[derive(Serialize)]
pub struct MplsLabelStackMember {
    pub label: u32,
    pub exp: u8,
    pub bos: u8,
    pub ttl: u8,
}

impl From<trippy_core::MplsLabelStackMember> for MplsLabelStackMember {
    fn from(value: trippy_core::MplsLabelStackMember) -> Self {
        Self {
            label: value.label,
            exp: value.exp,
            bos: value.bos,
            ttl: value.ttl,
        }
    }
}

impl Display for MplsLabelStackMember {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

#[derive(Serialize)]
pub struct UnknownExtension {
    pub class_num: u8,
    pub class_subtype: u8,
    pub bytes: Vec<u8>,
}

impl From<trippy_core::UnknownExtension> for UnknownExtension {
    fn from(value: trippy_core::UnknownExtension) -> Self {
        Self {
            class_num: value.class_num,
            class_subtype: value.class_subtype,
            bytes: value.bytes,
        }
    }
}

impl Display for UnknownExtension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown(class={}, subtype={}, bytes=[{:02x}])",
            self.class_num,
            self.class_subtype,
            self.bytes.iter().format(" ")
        )
    }
}

#[expect(clippy::trivially_copy_pass_by_ref)]
pub fn fixed_width<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{val:.2}"))
}
