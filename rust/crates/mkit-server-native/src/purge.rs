//! Signed global purge delivery over the native hook channel.
use crate::{
    config::{ConfigError, PREFIX},
    hooks::{HttpChannel, config::HookSettings},
    timers::TokioSleep,
};
use mkit_server::SystemClock;
use mkit_server::hooks::{HookClient, RemotePurge};
use std::sync::Arc;
/// Build a dedicated global purger; absence leaves the purge framework disabled.
/// # Errors
/// Invalid sink origin, signing key or audience.
pub fn build(
    settings: Option<&HookSettings>,
    audience: &str,
) -> Result<Option<RemotePurge<HttpChannel>>, ConfigError> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let Some(url) = &settings.purge else {
        return Ok(None);
    };
    let client = HookClient::new(
        HttpChannel::new(url).map_err(|e| {
            ConfigError::new(
                crate::exit::CONFIG_ERROR,
                format!("{PREFIX}: purge sink: {e}"),
            )
        })?,
        audience,
        Some(settings.signer()?),
        Arc::new(SystemClock),
        Arc::new(TokioSleep),
    )
    .map_err(|e| {
        ConfigError::new(
            crate::exit::CONFIG_ERROR,
            format!("{PREFIX}: purge sink: {e}"),
        )
    })?;
    Ok(Some(RemotePurge::new(Arc::new(client))))
}

/// Each native timer fire has its own budget; unlike a Worker alarm it does
/// not share an external-subrequest allowance with other partition heads.
pub(crate) struct NativeDelivery {
    delivery: mkit_server::purge::PurgeDelivery,
    budget: mkit_server::purge::SliceBudget,
}
impl NativeDelivery {
    pub(crate) fn new(sink: RemotePurge<HttpChannel>) -> Self {
        let budget = mkit_server::purge::SliceBudget::new(256);
        Self {
            delivery: mkit_server::purge::PurgeDelivery::new(
                Arc::new(mkit_server::purge::NoLocalCache),
                Some(Arc::new(sink)),
                budget.clone(),
            ),
            budget,
        }
    }
}
impl<S: mkit_server::NamespaceStore> mkit_server::timers::TimerHandler<S> for NativeDelivery {
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::CACHE_PURGE
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a mkit_server::timers::TimerCtx<'a, S>,
        timer: &'a mkit_server::timers::DueTimer,
    ) -> mkit_server::BoxFuture<'a, Result<mkit_server::timers::Fired, mkit_server::StoreError>>
    {
        self.budget.reset();
        mkit_server::timers::TimerHandler::fire(&self.delivery, ctx, timer)
    }
}
