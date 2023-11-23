use crate::backend;
use serde::{Serialize, Serializer};
use trippy::dns::Resolver;

#[derive(Serialize)]
pub struct Report {
    pub info: Info,
    pub hops: Vec<Hop>,
}

#[derive(Serialize)]
pub struct Info {
    pub target: Host,
}

#[derive(Serialize)]
pub struct Hop {
    ttl: u8,
    hosts: Vec<Host>,
    extensions: Extensions,
    #[serde(serialize_with = "fixed_width")]
    loss_pct: f64,
    sent: usize,
    #[serde(serialize_with = "fixed_width")]
    last: f64,
    recv: usize,
    #[serde(serialize_with = "fixed_width")]
    avg: f64,
    #[serde(serialize_with = "fixed_width")]
    best: f64,
    #[serde(serialize_with = "fixed_width")]
    worst: f64,
    #[serde(serialize_with = "fixed_width")]
    stddev: f64,
}

impl<R: Resolver> From<(&'_ backend::trace::Hop, &'_ R)> for Hop {
    fn from((value, resolver): (&backend::trace::Hop, &R)) -> Self {
        let hosts: Vec<_> = value
            .addrs()
            .map(|ip| Host {
                ip: ip.to_string(),
                hostname: resolver.reverse_lookup(*ip).to_string(),
            })
            .collect();
        let extensions = Extensions::from(
            value
                .extensions()
                .map(ToOwned::to_owned)
                .unwrap_or_default(),
        );
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
        }
    }
}

#[derive(Serialize)]
pub struct Host {
    pub ip: String,
    pub hostname: String,
}

#[derive(Serialize)]
#[serde(transparent)]
pub struct Extensions {
    pub extensions: Vec<Extension>,
}

impl From<trippy::tracing::Extensions> for Extensions {
    fn from(value: trippy::tracing::Extensions) -> Self {
        Self {
            extensions: value.extensions.into_iter().map(Extension::from).collect(),
        }
    }
}

#[derive(Serialize)]
pub enum Extension {
    #[serde(rename = "unknown")]
    Unknown(UnknownExtension),
    #[serde(rename = "mpls")]
    Mpls(MplsLabelStack),
}

impl From<trippy::tracing::Extension> for Extension {
    fn from(value: trippy::tracing::Extension) -> Self {
        match value {
            trippy::tracing::Extension::Unknown(unknown) => {
                Self::Unknown(UnknownExtension::from(unknown))
            }
            trippy::tracing::Extension::Mpls(mpls) => Self::Mpls(MplsLabelStack::from(mpls)),
        }
    }
}

#[derive(Serialize)]
pub struct MplsLabelStack {
    pub members: Vec<MplsLabelStackMember>,
}

impl From<trippy::tracing::MplsLabelStack> for MplsLabelStack {
    fn from(value: trippy::tracing::MplsLabelStack) -> Self {
        Self {
            members: value
                .members
                .into_iter()
                .map(MplsLabelStackMember::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub struct MplsLabelStackMember {
    pub label: u32,
    pub exp: u8,
    pub bos: u8,
    pub ttl: u8,
}

impl From<trippy::tracing::MplsLabelStackMember> for MplsLabelStackMember {
    fn from(value: trippy::tracing::MplsLabelStackMember) -> Self {
        Self {
            label: value.label,
            exp: value.exp,
            bos: value.bos,
            ttl: value.ttl,
        }
    }
}

#[derive(Serialize)]
pub struct UnknownExtension {
    pub class_num: u8,
    pub class_subtype: u8,
    pub bytes: Vec<u8>,
}

impl From<trippy::tracing::UnknownExtension> for UnknownExtension {
    fn from(value: trippy::tracing::UnknownExtension) -> Self {
        Self {
            class_num: value.class_num,
            class_subtype: value.class_subtype,
            bytes: value.bytes,
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn fixed_width<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{val:.2}"))
}