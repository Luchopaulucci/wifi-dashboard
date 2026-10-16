use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::{CoreError, Result};

use super::addr::is_public_ip;
use super::types::GeoInfo;

pub struct RateLimiter {
    last: Option<Instant>,
    min_interval: Duration,
}

impl RateLimiter {
    pub fn new(min_interval: Duration) -> Self {
        Self {
            last: None,
            min_interval,
        }
    }

    pub fn wait_if_needed(&mut self) {
        if let Some(last) = self.last {
            let elapsed = last.elapsed();
            if elapsed < self.min_interval {
                std::thread::sleep(self.min_interval - elapsed);
            }
        }
        self.last = Some(Instant::now());
    }
}

#[derive(Debug, Deserialize)]
struct IpApi {
    status: Option<String>,
    message: Option<String>,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn_line: Option<String>,
    asname: Option<String>,
    query: Option<String>,
}

pub fn parse_ip_api(json: &str) -> Result<GeoInfo> {
    let parsed: IpApi = serde_json::from_str(json).map_err(|e| CoreError::Parse(e.to_string()))?;
    if parsed.status.as_deref() == Some("fail") {
        return Err(CoreError::Parse(
            parsed.message.unwrap_or_else(|| "ip-api fail".into()),
        ));
    }
    let (asn, as_name) = split_as(parsed.asn_line.as_deref());
    Ok(GeoInfo {
        ip: parsed.query.unwrap_or_default(),
        country: parsed.country,
        country_code: parsed.country_code,
        isp: parsed.isp,
        org: parsed.org,
        asn,
        as_name: parsed.asname.or(as_name),
        source: "ip-api.com".into(),
        source_label: "consulta externa a ip-api.com (sin API key, máx. ~45/min, cacheada)".into(),
    })
}

fn split_as(line: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(line) = line else {
        return (None, None);
    };
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("AS").or_else(|| line.strip_prefix("as")) {
        let mut parts = rest.splitn(2, ' ');
        let num = parts.next().unwrap_or("").trim();
        let name = parts
            .next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if num.chars().all(|c| c.is_ascii_digit()) && !num.is_empty() {
            return (Some(format!("AS{num}")), name);
        }
    }
    (Some(line.to_string()), None)
}

#[derive(Debug, Deserialize)]
struct Rdap {
    name: Option<String>,
    country: Option<String>,
    #[serde(default)]
    remarks: Vec<RdapRemark>,
    #[serde(default)]
    entities: Vec<RdapEntity>,
}

#[derive(Debug, Deserialize)]
struct RdapRemark {
    description: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RdapEntity {
    #[serde(rename = "vcardArray")]
    vcard: Option<serde_json::Value>,
}

pub fn parse_rdap(json: &str, ip: &str) -> Result<GeoInfo> {
    let parsed: Rdap = serde_json::from_str(json).map_err(|e| CoreError::Parse(e.to_string()))?;
    let org = parsed.name.clone().or_else(|| {
        parsed
            .entities
            .iter()
            .filter_map(|e| vcard_fn(&e.vcard))
            .next()
    });
    let remark = parsed
        .remarks
        .iter()
        .filter_map(|r| r.description.as_ref())
        .flatten()
        .next()
        .cloned();
    Ok(GeoInfo {
        ip: ip.to_string(),
        country: parsed.country,
        country_code: None,
        isp: remark.clone(),
        org,
        asn: None,
        as_name: remark,
        source: "rdap.org".into(),
        source_label: "consulta externa a RDAP (fallback, sin API key, cacheada)".into(),
    })
}

fn vcard_fn(v: &Option<serde_json::Value>) -> Option<String> {
    let arr = v.as_ref()?.as_array()?;
    for item in arr {
        if let Some(inner) = item.as_array() {
            if inner.first()?.as_str()? == "fn" {
                return inner.last()?.as_str().map(|s| s.to_string());
            }
        }
    }
    None
}

pub fn lookup_ip_external(ip: &str) -> Result<GeoInfo> {
    let parsed: IpAddr = ip
        .parse()
        .map_err(|_| CoreError::InvalidArg(format!("ip: {ip}")))?;
    if !is_public_ip(parsed) {
        return Err(CoreError::Forbidden(
            "IP privada o no ruteable: no se consulta un servicio externo".into(),
        ));
    }
    // Solo IPs literales ya parseadas: no hay SSRF por hostname.
    let url = format!(
        "http://ip-api.com/json/{parsed}?fields=status,message,country,countryCode,isp,org,as,asname,query"
    );
    if let Ok(body) = http_get_json(&url) {
        if let Ok(mut info) = parse_ip_api(&body) {
            if info.ip.is_empty() {
                info.ip = parsed.to_string();
            }
            return Ok(info);
        }
    }
    let rdap = format!("https://rdap.org/ip/{parsed}");
    let body = http_get_json(&rdap)?;
    parse_rdap(&body, &parsed.to_string())
}

fn http_get_json(url: &str) -> Result<String> {
    let resp = ureq::get(url)
        .set("User-Agent", "Senal/0.1 (read-only network diagnostics; https://github.com/Luchopaulucci/wifi-dashboard)")
        .set("Accept", "application/json")
        .timeout(Duration::from_secs(6))
        .call()
        .map_err(|e| CoreError::CommandFailed {
            comando: "http".into(),
            detalle: e.to_string(),
        })?;
    resp.into_string()
        .map_err(|e| CoreError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_api_fixture() {
        let json = r#"{"status":"success","country":"United States","countryCode":"US","isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC","asname":"GOOGLE","query":"8.8.8.8"}"#;
        let g = parse_ip_api(json).unwrap();
        assert_eq!(g.ip, "8.8.8.8");
        assert_eq!(g.country_code.as_deref(), Some("US"));
        assert_eq!(g.asn.as_deref(), Some("AS15169"));
        assert_eq!(g.as_name.as_deref(), Some("GOOGLE"));
        assert!(g.source_label.contains("externa"));
    }

    #[test]
    fn rejects_private() {
        assert!(lookup_ip_external("192.168.0.1").is_err());
        assert!(lookup_ip_external("127.0.0.1").is_err());
        assert!(lookup_ip_external("not-an-ip").is_err());
    }
}
