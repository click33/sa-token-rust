// Author: 金书记 | Author: Jin Shuji
//! Dispatch push after releasing the pusher list lock.
//! 释放推送器列表锁后再逐个 await。

use std::sync::Arc;

use crate::error::SaTokenResult;
use crate::online::{MessagePusher, PushMessage};

/// Clone the pusher list, drop the lock, then await each pusher.
/// 先克隆列表并释放锁，再逐个 await，避免写锁（register_pusher）被饿死。
pub async fn dispatch_to_pushers(
    pushers: &[Arc<dyn MessagePusher>],
    login_id: &str,
    message: PushMessage,
) -> SaTokenResult<()> {
    for pusher in pushers {
        pusher.push(login_id, message.clone()).await?;
    }
    Ok(())
}
