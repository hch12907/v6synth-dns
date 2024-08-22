// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, net::Ipv4Addr, sync::Arc};

use hickory_proto::{
    error::ProtoErrorKind, op::Query, rr::{rdata::AAAA, RData}
};
use hickory_resolver::{error::ResolveErrorKind, lookup::Lookup, Hosts};
use hickory_resolver::name_server::TokioConnectionProvider;
use tracing::{debug, info};

use hickory_server::{
    authority::{
        Authority, LookupError, LookupObject, LookupOptions, MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, Record, RecordType},
    },
    resolver::{config::ResolverConfig, lookup::Lookup as ResolverLookup, TokioAsyncResolver},
    server::RequestInfo,
    store::forwarder::ForwardConfig,
};

use crate::script::{LoadedScripts, ScriptExecution};

/// An authority that will forward resolutions to upstream resolvers.
///
/// This uses the hickory-resolver for resolving requests.
pub struct V6SynthAuthority {
    origin: LowerName,
    resolver: TokioAsyncResolver,
    loaded_scripts: LoadedScripts,
    hosts: Option<Hosts>,
}

impl V6SynthAuthority {
    /// Read the Authority for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        _zone_type: ZoneType,
        config: &ForwardConfig,
        loaded_scripts: LoadedScripts,
    ) -> Result<Self, String> {
        info!("loading forwarder config: {}", origin);

        let name_servers = config.name_servers.clone();
        let mut options = config.options.clone().unwrap_or_default();

        // See RFC 1034, Section 4.3.2:
        // "If the data at the node is a CNAME, and QTYPE doesn't match
        // CNAME, copy the CNAME RR into the answer section of the response,
        // change QNAME to the canonical name in the CNAME RR, and go
        // back to step 1."
        //
        // Essentially, it's saying that servers (including forwarders)
        // should emit any found CNAMEs in a response ("copy the CNAME
        // RR into the answer section"). This is the behavior that
        // preserve_intermediates enables when set to true, and disables
        // when set to false. So we set it to true.
        if !options.preserve_intermediates {
            tracing::warn!(
                "preserve_intermediates set to false, which is invalid \
                for a forwarder; switching to true"
            );
            options.preserve_intermediates = true;
        }

        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let hosts = options.use_hosts_file.then(|| Hosts::new());

        let resolver = TokioAsyncResolver::new(config, options, TokioConnectionProvider::default());

        info!("forward resolver configured: {}: ", origin);

        // TODO: this might be infallible?
        Ok(Self {
            origin: origin.into(),
            resolver,
            loaded_scripts,
            hosts,
        })
    }
}

#[async_trait::async_trait]
impl Authority for V6SynthAuthority {
    type Lookup = ForwardLookup;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        debug!("forwarding lookup: {} {}", name, rtype);

        if (rtype == RecordType::A || rtype == RecordType::AAAA) && self.hosts.is_some() {
            let hosts = self.hosts.as_ref().unwrap();

            let mut name = Name::from(name.clone());
            name.set_fqdn(false);

            if let Some(lookup) = hosts.lookup_static_host(&Query::query(name, rtype)) {
                return Ok(ForwardLookup::Hosts(lookup))
            }
        };

        let resolve = self.resolver.lookup(name.clone(), rtype).await;

        // The client is looking for an IPv6 address to the domain. If the
        // upstream DNS server returns no AAAA record, we can intervene if
        // the website is behind a CDN
        let has_aaaa = resolve
            .as_ref()
            .map(|lookup| lookup.record_iter())
            .map(|mut recs| recs.any(|rec| rec.record_type() == RecordType::AAAA))
            .unwrap_or(false);

        if rtype == RecordType::AAAA && !has_aaaa  {
            info!(
                "{} is IPv4-only, yet AAAA was requested. Attempting AAAA synthesis",
                &name
            );

            let records = self
                .resolver
                .lookup(name.clone(), RecordType::A)
                .await
                .map(|lookup| {
                    lookup
                        .record_iter()
                        .map(|rec| rec.data().clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            for script in &self.loaded_scripts.scripts {
                // check if the address in A record is in range of any script
                let ipv4 = records
                    .iter()
                    .filter_map(|data| match data {
                        RData::A(a) => Some(a.0.clone()),
                        _ => None,
                    })
                    .filter_map(|addr| {
                        script
                            .ipv4_ranges()
                            .iter()
                            .filter(|network| network.contains(addr))
                            .nth(0)
                            .map(|network| (addr, network.prefix() as u32))
                    })
                    .nth(0);

                let cname = if !script.cname_filter().is_empty() {
                    records
                        .iter()
                        .filter_map(|data| match data {
                            RData::CNAME(cname) => Some(cname.0.to_string()),
                            _ => None,
                        })
                        .find(|cname| cname.ends_with(script.cname_filter()))
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                if (!script.ipv4_ranges().is_empty() && ipv4.is_some()) || !cname.is_empty() {
                    let (ipv4, size) = ipv4.unwrap_or((Ipv4Addr::new(0, 0, 0, 0), 0));

                    let aaaa = ScriptExecution::from_ast(script.ast())
                        .execute(name.to_string(), ipv4, size, cname, self.resolver.clone())
                        .await;

                    if let Some(ipv6) = aaaa {
                        let record = Record::from_rdata(name.into(), 1, RData::AAAA(AAAA(ipv6)));

                        let mut query = Query::new();
                        query.set_name(name.into()).set_query_type(RecordType::AAAA);

                        let lookup = Lookup::new_with_max_ttl(query, Arc::from([record]));

                        return Ok(ForwardLookup::Resolver(lookup));
                    }
                }
            }
        }

        resolve.map(ForwardLookup::Resolver).map_err(|e| match e.kind() {
            ResolveErrorKind::Proto(p) => match p.kind() {
                ProtoErrorKind::NoRecordsFound { response_code, .. } => {
                    LookupError::ResponseCode(*response_code)
                }
                _ => LookupError::ResolveError(e),
            },
            _ => LookupError::ResolveError(e),
        })
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the forwarder",
        )))
    }
}

/// A structure that holds the results of a forwarding lookup.
///
/// This exposes an iterator interface for consumption downstream.
#[derive(Debug, Clone)]
pub enum ForwardLookup {
    Hosts(Lookup),
    Resolver(ResolverLookup),
}

impl LookupObject for ForwardLookup {
    fn is_empty(&self) -> bool {
        match self {
            Self::Hosts(h) => h.is_empty(),
            Self::Resolver(r) => r.is_empty(),
        }
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        match self {
            Self::Hosts(h) => Box::new(h.record_iter()),
            Self::Resolver(r) => Box::new(r.record_iter()),
        }
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}
