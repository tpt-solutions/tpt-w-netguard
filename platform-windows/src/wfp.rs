// SPDX-License-Identifier: MIT OR Apache-2.0
//! WFP enforcement through the user-mode Application Layer Enforcement API. No kernel driver.
//!
//! Design notes:
//! * The engine session is **dynamic** (`FWPM_SESSION_FLAG_DYNAMIC`). Every provider, sublayer
//!   and filter we add is removed by Windows when the engine handle closes, including when the
//!   process crashes or is killed. There are no orphaned block rules after a crash, and nothing
//!   is left behind on uninstall. The app re-applies persisted rules at startup.
//! * Each rule is installed as one filter per ALE connect layer inside a single transaction, so
//!   a partial failure rolls back instead of leaving half a rule.
//! * Filter ordering comes from [`crate::plan`], which mirrors `tpt_netguard_core::policy`.
//! * Requires administrator rights to open the engine for writing.
//!
//! Note: this code path needs an elevated process to exercise; the precedence logic it relies on
//! is unit-tested in `plan.rs`.

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::ptr;

use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::policy::validate_rule;
use tpt_netguard_core::traits::{AppRule, FirewallBackend};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL, FWP_UINT64, FWP_VALUE0,
    FWP_VALUE0_0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::plan::{plan_panic, plan_rule, FilterAction, FilterSpec, Layer};

/// Stable identifiers for this product's WFP objects (fixed per product, not per install).
const PROVIDER_KEY: GUID = GUID::from_u128(0x6f1c_0a2e_5b7d_4c19_9e3a_2d8b_41f0_7c55);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x0b9e_4d21_7a3c_4e88_8f6d_1c5a_93e2_d470);
/// Sublayer weight; the default-allow fallback applies when no filter matches.
const SUBLAYER_WEIGHT: u16 = 0x8000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(rc: u32, what: &str) -> Result<()> {
    match rc {
        0 => Ok(()),
        ERROR_ACCESS_DENIED => Err(Error::Backend(format!(
            "{what}: access denied; run tpt-netguard as administrator to enforce firewall rules"
        ))),
        other => Err(Error::Backend(format!("{what}: WFP error 0x{other:08X}"))),
    }
}

fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}

struct Installed {
    rule: AppRule,
    filters: Vec<u64>,
}

pub struct WfpEnforcer {
    engine: HANDLE,
    rules: BTreeMap<i64, Installed>,
    panic_filters: Vec<u64>,
    /// Application ids (`FWP_BYTE_BLOB` contents) cached per executable path.
    app_ids: HashMap<String, Vec<u8>>,
}

impl WfpEnforcer {
    /// Open the engine and register this product's provider and sublayer.
    pub fn open() -> Result<Self> {
        let display = wide("TPT NetGuard");
        // SAFETY: all pointers passed to WFP reference locals that outlive the calls, and the
        // structures are zero-initialised before their documented fields are set.
        unsafe {
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            session.displayData.name = display.as_ptr() as *mut u16;

            let mut engine: HANDLE = std::mem::zeroed();
            check(
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut engine,
                ),
                "open WFP engine",
            )?;

            let mut provider: FWPM_PROVIDER0 = std::mem::zeroed();
            provider.providerKey = PROVIDER_KEY;
            provider.displayData = FWPM_DISPLAY_DATA0 {
                name: display.as_ptr() as *mut u16,
                description: display.as_ptr() as *mut u16,
            };
            let rc = FwpmProviderAdd0(engine, &provider, ptr::null_mut());
            if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
                FwpmEngineClose0(engine);
                check(rc, "register provider")?;
            }

            let mut provider_key = PROVIDER_KEY;
            let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
            sublayer.subLayerKey = SUBLAYER_KEY;
            sublayer.displayData = FWPM_DISPLAY_DATA0 {
                name: display.as_ptr() as *mut u16,
                description: display.as_ptr() as *mut u16,
            };
            sublayer.providerKey = &mut provider_key;
            sublayer.weight = SUBLAYER_WEIGHT;
            let rc = FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut());
            if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
                FwpmEngineClose0(engine);
                check(rc, "register sublayer")?;
            }

            Ok(Self {
                engine,
                rules: BTreeMap::new(),
                panic_filters: Vec::new(),
                app_ids: HashMap::new(),
            })
        }
    }

    fn app_id(&mut self, path: &str) -> Result<Vec<u8>> {
        if let Some(cached) = self.app_ids.get(path) {
            return Ok(cached.clone());
        }
        let wpath = wide(path);
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: on success WFP allocates `blob`; we copy its bytes and free it exactly once.
        unsafe {
            check(
                FwpmGetAppIdFromFileName0(wpath.as_ptr(), &mut blob),
                "resolve application id",
            )?;
            if blob.is_null() {
                return Err(Error::Backend("WFP returned no application id".into()));
            }
            let bytes = std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec();
            let mut raw = blob as *mut c_void;
            FwpmFreeMemory0(&mut raw);
            self.app_ids.insert(path.to_string(), bytes.clone());
            Ok(bytes)
        }
    }

    /// Install one planned filter and return its id.
    fn add_filter(&mut self, spec: &FilterSpec, name: &[u16]) -> Result<u64> {
        let app_bytes = match &spec.app {
            Some(app) => Some(self.app_id(app)?),
            None => None,
        };
        let mut blob = FWP_BYTE_BLOB {
            size: 0,
            data: ptr::null_mut(),
        };
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        if let Some(bytes) = &app_bytes {
            blob.size = bytes.len() as u32;
            blob.data = bytes.as_ptr() as *mut u8;
            // SAFETY: zeroed condition value, then only the active union member is written.
            let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
            value.r#type = FWP_BYTE_BLOB_TYPE;
            value.Anonymous.byteBlob = &mut blob;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: value,
            });
        }

        let mut weight = spec.weight;
        // SAFETY: every pointer refers to a local that lives until FwpmFilterAdd0 returns.
        unsafe {
            let mut filter: FWPM_FILTER0 = std::mem::zeroed();
            filter.displayData.name = name.as_ptr() as *mut u16;
            let mut provider_key = PROVIDER_KEY;
            filter.providerKey = &mut provider_key;
            filter.layerKey = layer_guid(spec.layer);
            filter.subLayerKey = SUBLAYER_KEY;
            filter.weight = FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight,
                },
            };
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = if conditions.is_empty() {
                ptr::null_mut()
            } else {
                conditions.as_mut_ptr()
            };
            let action: FWP_ACTION_TYPE = match spec.action {
                FilterAction::Block => FWP_ACTION_BLOCK,
                FilterAction::Permit => FWP_ACTION_PERMIT,
            };
            let mut fwp_action: FWPM_ACTION0 = std::mem::zeroed();
            fwp_action.r#type = action;
            filter.action = fwp_action;

            let mut id: u64 = 0;
            check(
                FwpmFilterAdd0(self.engine, &filter, ptr::null_mut(), &mut id),
                "add firewall filter",
            )?;
            Ok(id)
        }
    }

    fn delete_filters(&mut self, ids: &[u64]) -> Result<()> {
        for &id in ids {
            // SAFETY: deleting by id on our own open engine handle.
            check(
                unsafe { FwpmFilterDeleteById0(self.engine, id) },
                "remove filter",
            )?;
        }
        Ok(())
    }

    /// Install a set of specs atomically; on failure everything added is rolled back.
    fn install(&mut self, specs: &[FilterSpec], name: &str) -> Result<Vec<u64>> {
        let wname = wide(name);
        // SAFETY: transaction calls on our engine handle; aborted on any failure.
        unsafe { check(FwpmTransactionBegin0(self.engine, 0), "begin transaction")? };
        let mut added = Vec::with_capacity(specs.len());
        for spec in specs {
            match self.add_filter(spec, &wname) {
                Ok(id) => added.push(id),
                Err(e) => {
                    // SAFETY: as above.
                    unsafe { FwpmTransactionAbort0(self.engine) };
                    return Err(e);
                }
            }
        }
        // SAFETY: as above.
        if let Err(e) = unsafe { check(FwpmTransactionCommit0(self.engine), "commit transaction") }
        {
            unsafe { FwpmTransactionAbort0(self.engine) };
            return Err(e);
        }
        Ok(added)
    }
}

/// `FWP_E_ALREADY_EXISTS`: the provider or sublayer survived from an earlier run.
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

// SAFETY: the engine handle is an opaque WFP session token with no thread affinity, and the
// enforcer is only used through `&mut self`, so it is never accessed from two threads at once.
unsafe impl Send for WfpEnforcer {}

impl FirewallBackend for WfpEnforcer {
    fn list_rules(&self) -> Result<Vec<AppRule>> {
        Ok(self.rules.values().map(|i| i.rule.clone()).collect())
    }

    fn apply_rule(&mut self, rule: &AppRule) -> Result<()> {
        validate_rule(rule)?;
        if self.rules.contains_key(&rule.id) {
            self.remove_rule(rule.id)?;
        }
        let specs = plan_rule(rule);
        let filters = self.install(&specs, &format!("TPT NetGuard rule {}", rule.id))?;
        self.rules.insert(
            rule.id,
            Installed {
                rule: rule.clone(),
                filters,
            },
        );
        Ok(())
    }

    fn remove_rule(&mut self, id: i64) -> Result<()> {
        let installed = self
            .rules
            .remove(&id)
            .ok_or_else(|| Error::InvalidInput(format!("no rule with id {id}")))?;
        self.delete_filters(&installed.filters)
    }

    fn set_block_all(&mut self, enabled: bool) -> Result<()> {
        match (enabled, self.panic_filters.is_empty()) {
            (true, true) => {
                self.panic_filters = self.install(&plan_panic(), "TPT NetGuard panic button")?;
            }
            (false, false) => {
                let ids = std::mem::take(&mut self.panic_filters);
                self.delete_filters(&ids)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn block_all_enabled(&self) -> Result<bool> {
        Ok(!self.panic_filters.is_empty())
    }
}

impl Drop for WfpEnforcer {
    fn drop(&mut self) {
        // SAFETY: closing our own handle. Dynamic filters are removed by the engine here.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}
