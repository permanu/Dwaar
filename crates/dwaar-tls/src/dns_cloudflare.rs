// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Cloudflare DNS provider for ACME DNS-01 challenges.
//!
//! Uses Cloudflare's REST API to create and delete TXT records needed for
//! wildcard certificate validation. All HTTP is done in-process via `reqwest`
//! with `rustls` — the previous curl shell-out was removed in issue #147
//! because a compromised `curl` could intercept the API token passed via stdin.
//! With reqwest the token travels only inside the process, in a header value.

use async_trait::async_trait;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::dns::{DnsError, DnsProvider};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare DNS provider using API token authentication.
///
/// Requires a scoped API token with `Zone:DNS:Edit` permission for the
/// target zone. The token is passed via config: `tls { dns cloudflare <token> }`.
///
/// All HTTP is in-process via a shared `reqwest::Client` (issue #147).
/// The previous approach shelled out to curl with the token piped through
/// stdin; reqwest keeps the token inside the process as a header value and
/// never exposes it to the kernel's argument list.
#[derive(Debug)]
pub struct CloudflareDnsProvider {
    api_token: Zeroizing<String>,
    /// Reused across all Cloudflare API calls to amortise TLS handshakes.
    client: reqwest::Client,
}

impl CloudflareDnsProvider {
    pub fn new(api_token: impl Into<String>) -> Self {
        // 30-second total timeout matches the previous curl `--max-time 30`.
        // connect_timeout matches the previous `--connect-timeout 10`.
        let client = reqwest::Client::builder()
            .user_agent(concat!("dwaar-tls/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Cloudflare DNS HTTP client failed to build");

        Self {
            api_token: Zeroizing::new(api_token.into()),
            client,
        }
    }

    /// Execute an authenticated request against the Cloudflare API.
    ///
    /// The token is sent as a request header inside this process — it never
    /// appears in argv or environment variables, which is strictly safer than
    /// the previous curl approach even with stdin piping (issue #147).
    async fn cf_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, DnsError> {
        let mut req = self
            .client
            .request(method, url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_token.as_str()),
            )
            .header("Content-Type", "application/json");

        if let Some(payload) = body {
            req = req.json(&payload);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| DnsError::ApiRequest(format!("Cloudflare API request failed: {e}")))?;

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            DnsError::ApiRequest(format!("failed to parse Cloudflare response: {e}"))
        })?;

        Ok(json)
    }

    /// Look up the Cloudflare zone ID for a domain by walking up the labels.
    ///
    /// For `_acme-challenge.sub.example.com`, tries `sub.example.com` then
    /// `example.com` until it finds a matching zone.
    async fn find_zone_id(&self, domain: &str) -> Result<String, DnsError> {
        // Strip wildcard prefix if present (e.g. `*.example.com` → `example.com`)
        let domain = domain.strip_prefix("*.").unwrap_or(domain);

        // Walk up the domain labels to find the zone
        let mut candidate = domain.to_string();
        loop {
            if let Some(zone_id) = self.try_zone_lookup(&candidate).await? {
                return Ok(zone_id);
            }

            // Strip the leftmost label
            match candidate.find('.') {
                Some(pos) if pos + 1 < candidate.len() => {
                    candidate = candidate[pos + 1..].to_string();
                }
                _ => break,
            }
        }

        Err(DnsError::ZoneNotFound(domain.to_string()))
    }

    /// Try to find a zone matching exactly this name.
    async fn try_zone_lookup(&self, name: &str) -> Result<Option<String>, DnsError> {
        let url = format!("{CF_API_BASE}/zones?name={name}&status=active");

        let json = self.cf_request(reqwest::Method::GET, &url, None).await?;

        let success = json["success"].as_bool().unwrap_or(false);
        if !success {
            let errors = json["errors"].to_string();
            return Err(DnsError::ApiResponse {
                status: 0,
                body: errors,
            });
        }

        let results = json["result"].as_array();
        if let Some(zones) = results
            && let Some(zone) = zones.first()
            && let Some(id) = zone["id"].as_str()
        {
            return Ok(Some(id.to_string()));
        }

        Ok(None)
    }

    /// Create a DNS TXT record via the Cloudflare API.
    async fn create_record(
        &self,
        zone_id: &str,
        name: &str,
        value: &str,
    ) -> Result<String, DnsError> {
        let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records");
        let payload = serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": value,
            "ttl": 120
        });

        let json = self
            .cf_request(reqwest::Method::POST, &url, Some(payload))
            .await?;

        let success = json["success"].as_bool().unwrap_or(false);
        if !success {
            let errors = json["errors"].to_string();
            return Err(DnsError::ApiResponse {
                status: 0,
                body: errors,
            });
        }

        json["result"]["id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| DnsError::ApiRequest("missing record ID in response".to_string()))
    }

    /// Delete a DNS record. The `record_id` is in `zone_id:record_id` format.
    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), DnsError> {
        let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}");

        let json = self.cf_request(reqwest::Method::DELETE, &url, None).await?;

        let success = json["success"].as_bool().unwrap_or(false);
        if !success {
            warn!(
                record_id,
                "Cloudflare record deletion reported failure (may already be gone)"
            );
        }

        Ok(())
    }
}

#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String, DnsError> {
        let zone_id = self.find_zone_id(domain).await?;
        let record_name = format!("_acme-challenge.{domain}");

        debug!(domain, record_name, "creating Cloudflare TXT record");

        let record_id = self.create_record(&zone_id, &record_name, value).await?;

        // Encode both zone_id and record_id so we can delete later
        Ok(format!("{zone_id}:{record_id}"))
    }

    async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsError> {
        let (zone_id, cf_record_id) = record_id.split_once(':').ok_or_else(|| {
            DnsError::ApiRequest(format!(
                "invalid record ID format '{record_id}' — expected 'zone_id:record_id'"
            ))
        })?;

        debug!(zone_id, cf_record_id, "deleting Cloudflare TXT record");
        self.delete_record(zone_id, cf_record_id).await
    }

    fn name(&self) -> &'static str {
        "cloudflare"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_id_round_trip() {
        let combined = format!("{}:{}", "zone123", "rec456");
        let (zone, record) = combined.split_once(':').expect("split");
        assert_eq!(zone, "zone123");
        assert_eq!(record, "rec456");
    }

    #[test]
    fn http_client_builds() {
        // Smoke: reqwest async client for the Cloudflare provider constructs
        // without panicking. No network calls are made. Issue #147: curl
        // shell-out replaced with in-process reqwest.
        let provider = CloudflareDnsProvider::new("test-token");
        // Confirm the name() method is accessible — exercises the DnsProvider impl.
        assert_eq!(provider.name(), "cloudflare");
    }
}
