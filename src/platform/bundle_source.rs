//! [`PlatformBundleSource`] — a [`ContractSource`] backed by T03 over HTTP.
//!
//! Fetches the signed contract bundle from the T03 Contract Authority, optionally
//! verifies its ECDSA P-256 signature, and maps it into a [`ResolvedPolicy`].
//! Compose it with a binding resolver that reads the producer's T02 storage
//! (e.g. the `lance` feature's storaged-backed table) to get a fully
//! platform-wired engine.

use async_trait::async_trait;
use p256::ecdsa::VerifyingKey;

use crate::binding::DatasetRef;
use crate::contract_source::{Caller, ContractError, ContractSource};
use crate::platform::bundle::{map_bundle_to_policy, SignedBundleFile};
use crate::policy::ResolvedPolicy;

/// A contract source that fetches and (optionally) verifies T03 signed bundles.
pub struct PlatformBundleSource {
    base_url: String,
    client: reqwest::Client,
    verifying_key: Option<VerifyingKey>,
    auth_header: Option<(String, String)>,
}

impl PlatformBundleSource {
    /// Point at a T03 base URL (e.g. `https://t03.internal`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
            verifying_key: None,
            auth_header: None,
        }
    }

    /// Verify every bundle's signature against `vk`. Without this, signatures
    /// are not checked (trust is delegated to the transport).
    pub fn with_verifying_key(mut self, vk: VerifyingKey) -> Self {
        self.verifying_key = Some(vk);
        self
    }

    /// Send an auth header (e.g. `Authorization: Bearer …`) with each request.
    pub fn with_auth(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth_header = Some((name.into(), value.into()));
        self
    }

    async fn fetch(&self, contract_id: &str) -> Result<SignedBundleFile, ContractError> {
        let url = format!(
            "{}/v1/contracts/{}/bundle",
            self.base_url.trim_end_matches('/'),
            contract_id
        );
        let mut req = self.client.get(&url);
        if let Some((name, value)) = &self.auth_header {
            req = req.header(name, value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ContractError::Platform(format!("fetch {url}: {e}")))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ContractError::Platform(format!("read body {url}: {e}")))?;
        if !status.is_success() {
            return Err(ContractError::Platform(format!(
                "T03 returned {status} for {url}"
            )));
        }

        let file = SignedBundleFile::from_json(&body)
            .map_err(|e| ContractError::Platform(e.to_string()))?;
        if let Some(vk) = &self.verifying_key {
            file.verify(vk)
                .map_err(|e| ContractError::Platform(format!("bundle signature: {e}")))?;
        }
        Ok(file)
    }
}

#[async_trait]
impl ContractSource for PlatformBundleSource {
    async fn resolve(
        &self,
        dataset: &DatasetRef,
        caller: &Caller,
    ) -> Result<ResolvedPolicy, ContractError> {
        // On the platform, the dataset reference is the T03 contract id.
        let file = self.fetch(dataset.as_str()).await?;
        Ok(map_bundle_to_policy(&file, caller))
    }
}
