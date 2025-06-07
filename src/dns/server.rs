use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use trust_dns_server::authority::{
    Authority, Catalog, LookupError, MessageRequest, UpdateResult, ZoneType,
};
use trust_dns_server::client::rr::LowerName;
use trust_dns_server::proto::rr::{Name, RData, Record, RecordType};
use trust_dns_server::server::{RequestInfo, ServerFuture};
use trust_dns_server::store::in_memory::InMemoryAuthority;

use crate::crawler::crawler::Crawler;
use crate::{log_info, log_verbose};

const DEFAULT_DNS_PORT: u16 = 53; // Standard DNS port for production
const TTL: u32 = 300; // 5 minutes TTL for DNS records

/// Dynamic DNS Authority that queries the seeder for fresh node data on each request
pub struct DynamicPeercoinAuthority {
    static_authority: InMemoryAuthority,
    shared_seeder: Arc<tokio::sync::Mutex<Crawler>>,
    origin: Name,
}

impl DynamicPeercoinAuthority {
    pub fn new(
        static_authority: InMemoryAuthority,
        shared_seeder: Arc<tokio::sync::Mutex<Crawler>>,
    ) -> Self {
        let origin = static_authority.origin().clone().into();
        Self {
            static_authority,
            shared_seeder,
            origin,
        }
    }

    /// Get fresh A records from the seeder
    async fn get_fresh_a_records(&self) -> Vec<Record> {
        let top_nodes = {
            let seeder = self.shared_seeder.lock().await;
            // Use historical reliable nodes if available, otherwise fall back to current good nodes
            seeder.get_top_reliable_nodes(10).await
        };

        let mut records = Vec::new();
        for node in top_nodes {
            if let SocketAddr::V4(ipv4_addr) = node {
                let a_record = Record::new()
                    .set_name(self.origin.clone())
                    .set_ttl(TTL)
                    .set_record_type(RecordType::A)
                    .set_dns_class(trust_dns_server::proto::rr::DNSClass::IN)
                    .set_data(Some(RData::A(*ipv4_addr.ip())))
                    .clone();
                records.push(a_record);
            }
        }
        records
    }
}

#[async_trait::async_trait]
impl Authority for DynamicPeercoinAuthority {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;

    fn zone_type(&self) -> ZoneType {
        self.static_authority.zone_type()
    }

    fn is_axfr_allowed(&self) -> bool {
        self.static_authority.is_axfr_allowed()
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.static_authority.update(update).await
    }

    fn origin(&self) -> &LowerName {
        self.static_authority.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: trust_dns_server::authority::LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        // Increment DNS query counter
        crate::logging::increment_dns_queries();

        // For A record requests to our origin, return fresh data from seeder
        if rtype == RecordType::A && name == self.static_authority.origin() {
            log_verbose!("DNS A record request for {}", name);
            let fresh_records = self.get_fresh_a_records().await;
            if !fresh_records.is_empty() {
                log_verbose!("Serving {} A records from seeder", fresh_records.len());
                // Create a temporary in-memory authority with fresh records
                let temp_authority =
                    InMemoryAuthority::empty(self.origin.clone(), ZoneType::Primary, false);
                for record in fresh_records {
                    temp_authority.upsert(record, 0).await;
                }
                return temp_authority.lookup(name, rtype, lookup_options).await;
            }
        }

        // For all other requests (SOA, NS, etc.), use static authority
        self.static_authority
            .lookup(name, rtype, lookup_options)
            .await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: trust_dns_server::authority::LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        // Increment DNS query counter
        crate::logging::increment_dns_queries();

        // Check if this is an A record request for our origin
        let query = request_info.query;
        if query.query_type() == RecordType::A {
            let query_name: LowerName = query.name().clone();
            if query_name == *self.static_authority.origin() {
                log_verbose!("DNS A record search for {}", query_name);
                let fresh_records = self.get_fresh_a_records().await;
                if !fresh_records.is_empty() {
                    log_verbose!("Serving {} A records from seeder", fresh_records.len());
                    // Create a temporary in-memory authority with fresh records
                    let temp_authority =
                        InMemoryAuthority::empty(self.origin.clone(), ZoneType::Primary, false);
                    for record in fresh_records {
                        temp_authority.upsert(record, 0).await;
                    }
                    return temp_authority.search(request_info, lookup_options).await;
                }
            }
        }

        self.static_authority
            .search(request_info, lookup_options)
            .await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: trust_dns_server::authority::LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.static_authority
            .get_nsec_records(name, lookup_options)
            .await
    }
}

/// Start the DNS server with seeder integration using trust-dns-server library
pub async fn start_dns_server_with_seeder(
    hostname: Option<String>,
    nameserver: Option<String>,
    shared_seeder: Arc<tokio::sync::Mutex<Crawler>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Both hostname and nameserver must be provided
    let hostname = hostname.ok_or("Hostname is required for DNS server operation")?;
    let nameserver = nameserver.ok_or("Nameserver is required for DNS server operation")?;

    // Create socket address for binding
    let bind_addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), DEFAULT_DNS_PORT);

    log_info!(
        "DNS server starting on port {} with hostname: {} and nameserver: {}",
        DEFAULT_DNS_PORT,
        hostname,
        nameserver
    );

    // Create DNS authority zone for the hostname
    let mut catalog = Catalog::new();

    // Get the hostname as a domain name for the authority
    let origin =
        Name::from_ascii(&hostname).map_err(|_| format!("Invalid hostname: {}", hostname))?;

    // Get the nameserver as a domain name
    let nameserver_name =
        Name::from_ascii(&nameserver).map_err(|_| format!("Invalid nameserver: {}", nameserver))?;

    // Create dynamic DNS authority that will periodically update with peer data
    let static_authority = create_static_authority(origin.clone(), nameserver_name).await?;

    // Add the authority to the catalog
    let origin_lower: LowerName = origin.clone().into();
    catalog.upsert(
        origin_lower,
        Box::new(Arc::new(DynamicPeercoinAuthority::new(
            static_authority,
            shared_seeder,
        ))),
    );

    // Create DNS server
    let mut server = ServerFuture::new(catalog);

    // Create UDP socket
    let socket = UdpSocket::bind(bind_addr).await?;

    // Register socket with the server
    server.register_socket(socket);

    // Start the server
    server.block_until_done().await?;

    Ok(())
}

/// Create a static DNS authority with only SOA and NS records (A records are dynamic)
async fn create_static_authority(
    origin: Name,
    nameserver_name: Name,
) -> Result<InMemoryAuthority, Box<dyn std::error::Error>> {
    // Create an empty authority
    let authority = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);

    // Add SOA record
    let soa = Record::new()
        .set_name(origin.clone())
        .set_ttl(TTL)
        .set_record_type(RecordType::SOA)
        .set_dns_class(trust_dns_server::proto::rr::DNSClass::IN)
        .set_data(Some(RData::SOA(
            trust_dns_server::proto::rr::rdata::SOA::new(
                nameserver_name.clone(),                           // Primary nameserver
                Name::from_ascii("noreply.example.com.").unwrap(), // Admin contact
                1,                                                 // Serial
                3600,                                              // Refresh
                1800,                                              // Retry
                604800,                                            // Expire
                TTL,                                               // Minimum TTL
            ),
        )))
        .clone();

    authority.upsert(soa, 0).await;

    // Add NS record
    let ns = Record::new()
        .set_name(origin.clone())
        .set_ttl(TTL)
        .set_record_type(RecordType::NS)
        .set_dns_class(trust_dns_server::proto::rr::DNSClass::IN)
        .set_data(Some(RData::NS(nameserver_name)))
        .clone();

    authority.upsert(ns, 0).await;

    Ok(authority)
}
