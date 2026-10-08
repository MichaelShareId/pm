use anyhow::{bail, Context, Result};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::config::DataDir;
use crate::crypto::{master_key_from_hex, master_key_to_hex, MasterKey};

const SERVICE: &str = "pm.master-key";

fn account_for(data: &DataDir) -> String {
    // Scope the keychain item to this vault path so multiple PM_DATA dirs can coexist.
    account_for_path(data.root())
}

fn account_for_path(path: &std::path::Path) -> String {
    format!("pm:{}", path.display())
}

pub fn store_master_key(data: &DataDir, key: &MasterKey) -> Result<()> {
    let account = account_for(data);
    let hex = master_key_to_hex(key);
    let _ = delete_generic_password(SERVICE, &account);
    set_generic_password(SERVICE, &account, hex.as_bytes())
        .context("store master key in macOS Keychain")?;
    Ok(())
}

/// Keychain `errSecItemNotFound`.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Load this vault's master key; `Ok(None)` only when no Keychain item exists.
/// Other errors (e.g. a denied access prompt) are returned, never treated as "missing".
pub fn load_existing_master_key(data: &DataDir) -> Result<Option<MasterKey>> {
    if let Some(key) = load_from_account(&account_for(data))? {
        return Ok(Some(key));
    }
    // Older builds named the item after PM_DATA as typed (e.g. `./vault`, `vault/`).
    // Move such a key to the canonical account once.
    let legacy = account_for_path(data.as_given());
    if legacy == account_for(data) {
        return Ok(None);
    }
    let Some(key) = load_from_account(&legacy)? else {
        return Ok(None);
    };
    store_master_key(data, &key)?;
    let _ = delete_generic_password(SERVICE, &legacy);
    Ok(Some(key))
}

fn load_from_account(account: &str) -> Result<Option<MasterKey>> {
    match get_generic_password(SERVICE, account) {
        Ok(bytes) => {
            let s = std::str::from_utf8(&bytes).context("master key in Keychain is not UTF-8")?;
            master_key_from_hex(s).map(Some)
        }
        Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(err) => Err(err).context("load master key from macOS Keychain"),
    }
}

pub fn load_master_key(data: &DataDir) -> Result<MasterKey> {
    load_existing_master_key(data)?.context("master key not found in macOS Keychain")
}

#[cfg(target_os = "macos")]
pub fn ensure_touch_id(reason: &str) -> Result<()> {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSDate, NSError, NSRunLoop, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let context = unsafe { LAContext::new() };
    let mut policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

    if unsafe { context.canEvaluatePolicy_error(policy) }.is_err() {
        policy = LAPolicy::DeviceOwnerAuthentication;
        unsafe { context.canEvaluatePolicy_error(policy) }.map_err(|err| {
            anyhow::anyhow!(
                "Touch ID / device authentication unavailable: {}",
                err.localizedDescription()
            )
        })?;
    }

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let reason_ns = NSString::from_str(reason);

    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        } else if error.is_null() {
            Err("authentication failed".to_string())
        } else {
            // SAFETY: LA framework passes a valid NSError when success is false.
            let err =
                unsafe { Retained::retain(error) }.expect("NSError from LocalAuthentication");
            Err(err.localizedDescription().to_string())
        };
        let _ = tx.send(result);
    });

    unsafe {
        context.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &reply);
    }

    // CLI tools must pump the run loop so the Touch ID UI can complete.
    let deadline = Instant::now() + Duration::from_secs(120);
    let outcome = loop {
        if let Ok(result) = rx.try_recv() {
            break result;
        }
        if Instant::now() > deadline {
            bail!("Touch ID prompt timed out");
        }
        let run_loop = NSRunLoop::currentRunLoop();
        let until = NSDate::dateWithTimeIntervalSinceNow(0.1);
        run_loop.runUntilDate(&until);
    };
    drop(context);

    match outcome {
        Ok(()) => Ok(()),
        Err(msg) => bail!("Touch ID authentication failed: {msg}"),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn ensure_touch_id(_reason: &str) -> Result<()> {
    bail!("Touch ID is only supported on macOS");
}
