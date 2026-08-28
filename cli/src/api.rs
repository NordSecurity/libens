#![allow(dead_code)]

use serde::Deserialize;

const API_BASE: &str = "https://api.nordvpn.com";
const CREDENTIALS_PATH: &str = "/v1/users/services/credentials";

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceCredentials {
    pub id: i64,
    pub created_at: String,
    pub updated_at: String,
    pub username: String,
    pub password: String,
    pub nordlynx_private_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unauthorized (token invalid or expired)")]
    Unauthorized,
    #[error("unexpected status {status}: {body}")]
    UnexpectedStatus { status: u16, body: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Technology {
    OpenVpnUdp,
    OpenVpnTcp,
    OpenVpnUdpObfuscated,
    OpenVpnTcpObfuscated,
    WireGuard,
    NordWhisper,

    Other(i64),
}

impl Technology {
    pub fn id(self) -> i64 {
        match self {
            Technology::OpenVpnUdp => 3,
            Technology::OpenVpnTcp => 5,
            Technology::OpenVpnUdpObfuscated => 15,
            Technology::OpenVpnTcpObfuscated => 17,
            Technology::WireGuard => 35,
            Technology::NordWhisper => 51,
            Technology::Other(id) => id,
        }
    }
}

impl From<i64> for Technology {
    fn from(id: i64) -> Self {
        match id {
            3 => Technology::OpenVpnUdp,
            5 => Technology::OpenVpnTcp,
            15 => Technology::OpenVpnUdpObfuscated,
            17 => Technology::OpenVpnTcpObfuscated,
            35 => Technology::WireGuard,
            51 => Technology::NordWhisper,
            other => Technology::Other(other),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Technology {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Technology::from(i64::deserialize(d)?))
    }
}

impl serde::Serialize for Technology {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(self.id())
    }
}

impl std::fmt::Display for Technology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub id: i64,
    pub created_at: String,
    pub name: String,
    pub station: String,
    pub hostname: String,
    pub load: i64,
    pub status: String,
    #[serde(default)]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub technologies: Vec<ServerTechnology>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub specifications: Vec<Specification>,
    #[serde(default)]
    pub ips: Vec<ServerIpRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    pub country: Country,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Country {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub city: Option<City>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct City {
    pub id: i64,
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
    pub hub_score: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerTechnology {
    pub id: Technology,
    pub pivot: Pivot,
    #[serde(default)]
    pub metadata: Vec<TechnologyMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pivot {
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TechnologyMetadata {
    pub name: Option<String>,
    /// Free-form; for WireGuard this is where you find `public_key`.
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    pub id: i64,
    pub title: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Specification {
    pub identifier: String,
    pub values: Vec<SpecificationValue>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpecificationValue {
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerIpRecord {
    pub ip: ServerIp,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerIp {
    pub ip: String,
    pub version: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum ServersError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unexpected status {status}: {body}")]
    UnexpectedStatus { status: u16, body: String },
}

fn client(user_agent: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .gzip(true)
        .build()
}

pub struct ApiClient {
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(user_agent: &str) -> Result<Self, reqwest::Error> {
        let client = client(user_agent)?;
        Ok(Self { client })
    }

    /// Fetch the VPN service credentials for the given NordVPN access token.
    ///
    /// The token is what `nordvpn token` prints, or what you pass to
    /// `nordvpn login --token`. The auth header format is the NordVPN-specific
    /// `Authorization: Bearer token:<TOKEN>` (note the literal `token:` prefix).
    pub async fn get_service_credentials(
        &self,
        token: &str,
    ) -> Result<ServiceCredentials, CredentialsError> {
        let resp = self
            .client
            .get(format!("{API_BASE}{CREDENTIALS_PATH}"))
            .header("Authorization", format!("Bearer token:{token}"))
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(CredentialsError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CredentialsError::UnexpectedStatus {
                status: status.as_u16(),
                body,
            });
        }

        Ok(resp.json::<ServiceCredentials>().await?)
    }

    /// Fetch every online server. Big response (~1.5 MB gzipped, ~15 MB raw).
    ///
    /// Mirrors the daemon's `/v1/servers?limit=…&filters[servers.status]=online&fields[…]`
    /// query with the same field selection it uses to keep the payload small.
    pub async fn list_all_servers(&self) -> Result<Vec<Server>, ServersError> {
        // Field selection kept identical to nordvpn-linux/core/urls.go:ServersURLConnectQuery.
        let url = format!(
            "{API_BASE}/v1/servers?limit=1073741824\
        &filters[servers.status]=online\
        &fields[servers.id]&fields[servers.name]&fields[servers.hostname]\
        &fields[servers.station]&fields[servers.status]&fields[servers.load]\
        &fields[servers.created_at]\
        &fields[servers.groups.id]&fields[servers.groups.title]\
        &fields[servers.technologies.id]&fields[servers.technologies.metadata]\
        &fields[servers.technologies.pivot.status]\
        &fields[servers.specifications.identifier]&fields[servers.specifications.values.value]\
        &fields[servers.locations.country.id]&fields[servers.locations.country.name]\
        &fields[servers.locations.country.code]\
        &fields[servers.locations.country.city.id]&fields[servers.locations.country.city.name]\
        &fields[servers.locations.country.city.latitude]\
        &fields[servers.locations.country.city.longitude]\
        &fields[servers.locations.country.city.hub_score]\
        &fields[servers.ips]"
        );
        self.fetch_servers(&url).await
    }

    async fn fetch_servers(&self, url: &str) -> Result<Vec<Server>, ServersError> {
        let resp = self
            .client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ServersError::UnexpectedStatus {
                status: status.as_u16(),
                body,
            });
        }
        Ok(resp.json::<Vec<Server>>().await?)
    }

    pub async fn get_server_by_id(&self, id: i64) -> Result<Option<Server>, ServersError> {
        let url = format!("{API_BASE}/v1/servers?filters[servers.id]={id}");
        let mut servers = self.fetch_servers(&url).await?;
        Ok(servers.pop())
    }

    pub async fn get_server_by_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<Server>, ServersError> {
        let url = format!("{API_BASE}/v1/servers?filters[servers.hostname]={hostname}");
        let mut servers = self.fetch_servers(&url).await?;
        Ok(servers.pop())
    }

    pub async fn get_server_by_ip(&self, ip: &str) -> Result<Option<Server>, ServersError> {
        let servers = self.list_all_servers().await?;
        Ok(servers
            .into_iter()
            .find(|s| s.ips.iter().any(|r| r.ip.ip == ip)))
    }
}
