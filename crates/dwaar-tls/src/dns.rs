// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! DNS provider trait for ACME DNS-01 challenges.
//!
//! Wildcard certificates (`*.example.com`) require DNS-01 validation — the
//! ACME server verifies a TXT record at `_acme-challenge.{domain}`. This
//! trait abstracts the DNS record creation/deletion so providers (Cloudflare,
//! Route53, etc.) can be swapped without touching the ACME core.

use async_trait::async_trait;

/// Errors from DNS provider operations.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS API request failed: {0}")]
    ApiRequest(String),

    #[error("DNS API returned error: {status} — {body}")]
    ApiResponse { status: u16, body: String },

    #[error("zone not found for domain '{0}'")]
    ZoneNotFound(String),

    #[error("DNS record propagation timed out for {domain} after {elapsed_secs}s")]
    PropagationTimeout { domain: String, elapsed_secs: u64 },

    #[error("DNS propagation check failed: {0}")]
    PropagationCheck(String),
}

/// Trait for DNS providers that can manage TXT records for ACME DNS-01 challenges.
///
/// Implementations make API calls to a DNS provider (Cloudflare, Route53, etc.)
/// to create and delete the `_acme-challenge.{domain}` TXT record needed for
/// wildcard cert validation.
#[async_trait]
pub trait DnsProvider: Send + Sync + std::fmt::Debug {
    /// Create a TXT record at `_acme-challenge.{domain}` with the given value.
    ///
    /// Returns a provider-specific record ID used for cleanup via `delete_txt_record`.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String, DnsError>;

    /// Delete a TXT record by its provider-specific ID.
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsError>;

    /// Provider name for logging (e.g. "cloudflare").
    fn name(&self) -> &'static str;
}

/// Check whether a DNS TXT record has propagated by shelling out to `dig`.
///
/// Uses `dig +short TXT _acme-challenge.{domain}` and checks if the expected
/// value appears in the output. Falls back gracefully if `dig` isn't available.
pub async fn check_txt_propagated(domain: &str, expected_value: &str) -> Result<bool, DnsError> {
    let fqdn = format!("_acme-challenge.{domain}");

    let output = tokio::process::Command::new("dig")
        .args(["+short", "TXT", &fqdn])
        .output()
        .await
        .map_err(|e| DnsError::PropagationCheck(format!("failed to run dig: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // dig returns TXT values in double quotes, e.g. `"abc123"`
    Ok(stdout.contains(expected_value))
}

/// Poll DNS until the TXT record is visible, with exponential backoff.
///
/// Retries: 1s, 2s, 4s, 8s, 16s, 32s, 32s, 32s... up to `max_wait_secs` total.
/// Returns `Ok(())` when the record is visible, or `Err(PropagationTimeout)` on timeout.
pub async fn wait_for_propagation(
    domain: &str,
    expected_value: &str,
    max_wait_secs: u64,
) -> Result<(), DnsError> {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let max_wait = Duration::from_secs(max_wait_secs);
    let mut delay = Duration::from_secs(1);
    let max_delay = Duration::from_secs(32);

    loop {
        match check_txt_propagated(domain, expected_value).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            // If dig fails, keep trying — it might be a transient issue
            Err(e) => {
                tracing::debug!(domain, error = %e, "DNS propagation check failed, retrying");
            }
        }

        if start.elapsed() >= max_wait {
            return Err(DnsError::PropagationTimeout {
                domain: domain.to_string(),
                elapsed_secs: start.elapsed().as_secs(),
            });
        }

        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(max_delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Mock DNS provider for testing the ACME DNS-01 flow without real API calls.
    #[derive(Debug, Clone)]
    pub(super) struct MockDnsProvider {
        pub(super) records: Arc<Mutex<Vec<(String, String, String)>>>, // (domain, value, id)
        next_id: Arc<Mutex<u64>>,
    }

    impl MockDnsProvider {
        pub(super) fn new() -> Self {
            Self {
                records: Arc::new(Mutex::new(Vec::new())),
                next_id: Arc::new(Mutex::new(1)),
            }
        }
    }

    #[async_trait]
    impl DnsProvider for MockDnsProvider {
        async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String, DnsError> {
            let mut id_lock = self.next_id.lock().await;
            let id = format!("mock-record-{}", *id_lock);
            *id_lock += 1;

            self.records
                .lock()
                .await
                .push((domain.to_string(), value.to_string(), id.clone()));

            Ok(id)
        }

        async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsError> {
            let mut records = self.records.lock().await;
            records.retain(|(_, _, id)| id != record_id);
            Ok(())
        }

        fn name(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn mock_provider_create_and_delete() {
        let provider = MockDnsProvider::new();

        let id = provider
            .create_txt_record("example.com", "test-value")
            .await
            .expect("create");
        assert_eq!(id, "mock-record-1");

        let records = provider.records.lock().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "example.com");
        assert_eq!(records[0].1, "test-value");
        drop(records);

        provider.delete_txt_record(&id).await.expect("delete");
        assert!(provider.records.lock().await.is_empty());
    }

    #[tokio::test]
    async fn mock_provider_multiple_records() {
        let provider = MockDnsProvider::new();

        let id1 = provider
            .create_txt_record("a.com", "val1")
            .await
            .expect("create 1");
        let id2 = provider
            .create_txt_record("b.com", "val2")
            .await
            .expect("create 2");

        assert_ne!(id1, id2);
        assert_eq!(provider.records.lock().await.len(), 2);

        // Delete first, second remains
        provider.delete_txt_record(&id1).await.expect("delete 1");
        let records = provider.records.lock().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "b.com");
    }
}
