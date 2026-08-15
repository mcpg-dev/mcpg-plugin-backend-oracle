//! cdylib sync bridge — adapts the async [`OracleBackendPlugin`] onto the sync
//! FFI trait the cdylib vtable expects ([`SyncBackendPlugin`]). A private
//! multi-thread runtime `block_on`s the async methods; the make-time
//! [`HostHandle`] is wrapped as `Arc<dyn BackendHost>` for `register_profile`
//! and installed on the inner plugin for observability. Oracle is
//! request/reply, so it inherits the SDK's single-`Done` streaming default.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest, ResourcePage,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::OracleBackendPlugin;
use crate::watch::OracleWatchCdylib;

fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("oracle cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`OracleBackendPlugin`].
pub struct OracleBackendCdylib {
    inner: OracleBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl OracleBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — Oracle carries no
    /// plugin-level config (per-binding connection / query arrive via
    /// `register_profile`).
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = OracleBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-oracle"),
        }
    }
}

impl SyncBackendPlugin for OracleBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }

    fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        self.rt.block_on(BackendPlugin::list_resources(
            &self.inner,
            profile_name,
            cursor,
        ))
    }

    fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        self.rt.block_on(BackendPlugin::complete_template_variable(
            &self.inner,
            profile_name,
            variable_name,
            prefix,
            config,
            context,
        ))
    }
}

// cdylib export — two entities under `dev.mcpg.backend.oracle`: the `backend`
// binding and the `watch_strategy` poller (kind `oracle_poll`). Oracle is
// network-only (ODPI-C dials the listener), so the single static capability is
// `NetworkOutbound` — matching the plugin.yaml `network_outbound` entry; the
// poll watcher uses the same outbound capability for its tracking query. The
// watch entity self-describes via its `manifest()` slot and is distinguished by
// its `inner_name` slug.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.oracle",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: OracleBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                OracleBackendCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch {
            inner_name: "watch",
            plugin_type: OracleWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                OracleWatchCdylib::from_host_config(cfg, host),
        },
    ],
}
