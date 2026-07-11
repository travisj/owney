//! Where does mail for a domain go? MX resolution in production, a fixed
//! relay in smarthost mode, and injectable routes in tests.

use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::{RData, rdata::MX};

use crate::DeliveryError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub host: String,
    pub port: u16,
}

pub trait Router: Send + Sync + 'static {
    /// Relays to try, in order of preference.
    fn resolve(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<Relay>, DeliveryError>> + Send;
}

/// RFC 5321 §5.1: MX records by preference; no MX → implicit MX on the
/// domain's A/AAAA; null MX (RFC 7505) → permanent refusal.
#[derive(Debug)]
pub struct MxRouter {
    resolver: hickory_resolver::TokioResolver,
}

impl MxRouter {
    pub fn new() -> Result<Self, DeliveryError> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|err| DeliveryError::Dns(err.to_string()))?
            .build()
            .map_err(|err| DeliveryError::Dns(err.to_string()))?;
        Ok(Self { resolver })
    }
}

impl Router for MxRouter {
    async fn resolve(&self, domain: &str) -> Result<Vec<Relay>, DeliveryError> {
        match self.resolver.mx_lookup(domain).await {
            Ok(lookup) => {
                let mut records: Vec<&MX> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::MX(mx) => Some(mx),
                        _ => None,
                    })
                    .collect();
                if records.len() == 1 && records[0].preference == 0 && records[0].exchange.is_root()
                {
                    // Null MX: the domain explicitly receives no mail.
                    return Err(DeliveryError::Permanent(format!(
                        "{domain} publishes a null MX (does not accept mail)"
                    )));
                }
                if records.is_empty() {
                    // Implicit MX: fall back to the domain itself.
                    return Ok(vec![Relay {
                        host: domain.to_owned(),
                        port: 25,
                    }]);
                }
                records.sort_by_key(|mx| mx.preference);
                Ok(records
                    .into_iter()
                    .map(|mx| Relay {
                        host: mx.exchange.to_utf8().trim_end_matches('.').to_owned(),
                        port: 25,
                    })
                    .collect())
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(_))) => {
                // Implicit MX: fall back to the domain itself.
                Ok(vec![Relay {
                    host: domain.to_owned(),
                    port: 25,
                }])
            }
            Err(err) => Err(DeliveryError::Dns(err.to_string())),
        }
    }
}

/// Fixed relay for every domain: smarthost mode in production, loopback in
/// tests.
#[derive(Debug, Clone)]
pub struct StaticRouter {
    pub relay: Relay,
}

impl Router for StaticRouter {
    async fn resolve(&self, _domain: &str) -> Result<Vec<Relay>, DeliveryError> {
        Ok(vec![self.relay.clone()])
    }
}

/// Runtime-selected routing mode (config decides at startup).
#[derive(Debug)]
pub enum AnyRouter {
    Mx(Box<MxRouter>),
    Static(StaticRouter),
}

impl Router for AnyRouter {
    async fn resolve(&self, domain: &str) -> Result<Vec<Relay>, DeliveryError> {
        match self {
            AnyRouter::Mx(router) => router.resolve(domain).await,
            AnyRouter::Static(router) => router.resolve(domain).await,
        }
    }
}
