//! Assemble the pipeline's hooks and kind-8 sink from [`HookSettings`].

use std::sync::Arc;

use mkit_server::SystemClock;
use mkit_server::hooks::{HookClient, RemoteAdmission, RemoteAuthorizer, RemoteOutcomes};
use mkit_server::pipeline::{
    Choice, DefaultAdmission, Hooks, NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer,
};

use super::HttpChannel;
use super::config::HookSettings;
use crate::config::{ConfigError, PREFIX};
use crate::exit;
use crate::timers::TokioSleep;

/// The authorizer: open, or the remote hook.
pub type NativeAuthorizer = Choice<OpenAuthorizer, RemoteAuthorizer<HttpChannel>>;
/// Admission: the built-in quota, or the remote hook.
pub type NativeAdmission = Choice<DefaultAdmission, RemoteAdmission<HttpChannel>>;
/// The kind-8 sink: the local acknowledger, or the remote hook.
pub type NativeSink = Choice<NoOutcomes, RemoteOutcomes<HttpChannel>>;
/// The hooks `mkit-server serve` runs.
pub type NativeHooks = Hooks<NativeAuthorizer, NativeAdmission>;

/// What [`build`] produces.
#[derive(Debug, Clone)]
pub struct Built {
    /// Stages 2 and 3.
    pub hooks: NativeHooks,
    /// Stage 8, for kind 8 (`open_with`).
    pub sink: NativeSink,
    /// Whether the sink is remote (a real delivery, which needs the timer
    /// driver).
    pub remote_sink: bool,
}

fn config_error(what: &str, why: impl core::fmt::Display) -> ConfigError {
    ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {what}: {why}"))
}

/// Build the hooks for `settings` (none: the built-in defaults).
/// `server_audience` is this server's canonical origin, taken from
/// [`crate::server::outcome_audience`] so an Admit and the Outcome of its
/// reservation name one origin (R-162). Roles with one base URL share a client.
///
/// # Errors
/// `CONFIG_ERROR` for a URL or key a client refuses.
pub fn build(settings: Option<&HookSettings>, server_audience: &str) -> Result<Built, ConfigError> {
    let mut hooks = Hooks {
        authorizer: Choice::Left(OpenAuthorizer),
        admission: Choice::Left(DefaultAdmission),
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let mut sink = Choice::Left(NoOutcomes);
    let Some(settings) = settings else {
        return Ok(Built {
            hooks,
            sink,
            remote_sink: false,
        });
    };
    let mut clients: Vec<(String, Arc<HookClient<HttpChannel>>)> = Vec::new();
    let mut client_for =
        |flag: &str, url: &str| -> Result<Arc<HookClient<HttpChannel>>, ConfigError> {
            let base = super::http::canonical_base(url).map_err(|e| config_error(flag, e))?;
            if let Some((_, client)) = clients.iter().find(|(known, _)| *known == base) {
                return Ok(Arc::clone(client));
            }
            let client = Arc::new(
                HookClient::new(
                    HttpChannel::new(url).map_err(|e| config_error(flag, e))?,
                    server_audience,
                    Some(settings.signer()?),
                    Arc::new(SystemClock),
                    Arc::new(TokioSleep),
                )
                .map_err(|e| config_error(flag, e))?,
            );
            clients.push((base, Arc::clone(&client)));
            Ok(client)
        };
    if let Some(url) = &settings.authorize {
        let client = client_for("--hook-authorize-url", url)?;
        hooks.authorizer =
            Choice::Right(RemoteAuthorizer::new(client).with_timeout(settings.timeout));
    }
    if let Some(url) = &settings.admit {
        let client = client_for("--hook-admit-url", url)?;
        hooks.admission =
            Choice::Right(RemoteAdmission::new(client).with_timeout(settings.timeout));
    }
    let mut remote_sink = false;
    if let Some(url) = &settings.outcome {
        let client = client_for("--hook-outcome-url", url)?;
        sink = Choice::Right(RemoteOutcomes::new(client).with_timeout(settings.timeout));
        remote_sink = true;
    }
    Ok(Built {
        hooks,
        sink,
        remote_sink,
    })
}

/// Refuse a hook key equal to the enc listener's server key (SPEC-SERVER
/// §7.1). The enc key may be created on first run, so this runs after it
/// loads.
///
/// # Errors
/// `CONFIG_ERROR` when the two are one key.
#[cfg(feature = "enc")]
pub fn check_enc_separation(
    settings: &HookSettings,
    key: &commonware_cryptography::ed25519::PrivateKey,
) -> Result<(), ConfigError> {
    use commonware_cryptography::Signer as _;

    let enc = <[u8; 32]>::try_from(key.public_key().as_ref())
        .map_err(|_| config_error("--enc-server-key", "not a 32-byte ed25519 key"))?;
    super::config::check_key_separation(&settings.public_key()?, &[("enc server key", &enc)])
}
