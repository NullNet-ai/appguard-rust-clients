use crate::{context::Context, token_provider::RetrievalStrategy};
use std::time::Duration;

pub async fn post_startup(context: Context) {
    let timeout = Duration::from_secs(10);

    let token = context
        .token_provider
        .obtain(RetrievalStrategy::Await(timeout))
        .await;

    if token.is_none() {
        log::error!("Failed to obtain auth token");
    }
}
