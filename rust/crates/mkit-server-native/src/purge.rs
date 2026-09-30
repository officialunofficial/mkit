//! Signed global purge delivery over the native hook channel.
use std::sync::Arc;
use mkit_server::{SystemClock, purge::{PurgeConfig, PurgeDelivery}};
use mkit_server::hooks::{HookClient, RemotePurge};
use crate::{config::{ConfigError, PREFIX}, hooks::{HttpChannel, config::HookSettings}, timers::TokioSleep};
/// Build a dedicated global purger; absence leaves the purge framework disabled.
/// # Errors
/// Invalid sink origin, signing key or audience.
pub fn build(settings:Option<&HookSettings>, audience:&str) -> Result<Option<RemotePurge<HttpChannel>>,ConfigError> {
    let Some(settings) = settings else { return Ok(None); };
    let Some(url) = &settings.purge else { return Ok(None); };
    let client = HookClient::new(HttpChannel::new(url)?, audience, Some(settings.signer()?), Arc::new(SystemClock), Arc::new(TokioSleep)).map_err(|e| ConfigError::new(crate::exit::CONFIG_ERROR,format!("{PREFIX}: purge sink: {e}")))?;
    Ok(Some(RemotePurge::new(Arc::new(client))))
}
