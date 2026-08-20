// Author: 金书记 | Author: Jin Shuji
//
//! Sharded Grant Cache | 分片授权缓存
//!
//! 权限/角色读缓存。默认**关闭**（`SaTokenConfig::grant_cache_ttl <= 0` 时
//! 连结构都不分配），因为多实例部署下缓存意味着授权变更存在滞后窗口，
//! 必须由使用者显式权衡后开启。
//!
//! Read cache for permissions and roles. Disabled by default — when
//! `grant_cache_ttl <= 0` no structure is even allocated — because in a
//! multi-instance deployment a cache introduces a staleness window for
//! authorization decisions, which must be an explicit opt-in.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::config::SaTokenConfig;
use crate::error::SaTokenResult;

/// 分片数量：必须是 2 的幂，以便用位与代替取模。
/// Shard count; must be a power of two so the index can use a bitmask.
const SHARD_COUNT: usize = 8;

/// 分片掩码 | Shard bitmask
const SHARD_MASK: usize = SHARD_COUNT - 1;

/// 缓存键内部分隔符
/// Internal key separator.
const KEY_SEP: char = '\u{1}';

/// 缓存数据类别 | Cached data kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    /// 权限列表 | Permission list
    Permission,
    /// 角色列表 | Role list
    Role,
}

impl GrantKind {
    /// 键前缀标记 | Key tag
    #[inline]
    fn tag(self) -> char {
        match self {
            Self::Permission => 'p',
            Self::Role => 'r',
        }
    }
}

/// 缓存条目 | Cache entry
struct CacheEntry {
    value: Arc<[String]>,
    expires_at: Instant,
}

type FlightMap = HashMap<String, Arc<tokio::sync::Mutex<()>>>;
type FlightShards = Box<[tokio::sync::Mutex<FlightMap>]>;

/// 分片授权缓存 | Sharded grant cache
pub struct GrantCache {
    shards: Box<[RwLock<HashMap<String, CacheEntry>>]>,
    /// 单飞门闩也按分片，避免全局一把 Mutex 串行。
    /// Single-flight gates are sharded too, avoiding one global Mutex.
    flights: FlightShards,
    ttl: Duration,
    max_per_shard: usize,
    single_flight: bool,
}

impl std::fmt::Debug for GrantCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantCache")
            .field("ttl", &self.ttl)
            .field("max_per_shard", &self.max_per_shard)
            .field("single_flight", &self.single_flight)
            .finish()
    }
}

impl GrantCache {
    /// 构造缓存 | Construct the cache
    pub fn new(ttl: Duration, max_entries: usize, single_flight: bool) -> Self {
        let max_per_shard = (max_entries / SHARD_COUNT).max(1);
        let shards = (0..SHARD_COUNT)
            .map(|_| RwLock::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let flights = (0..SHARD_COUNT)
            .map(|_| tokio::sync::Mutex::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            flights,
            ttl,
            max_per_shard,
            single_flight,
        }
    }

    /// 依配置构造；返回 `None` 表示**缓存关闭**。
    /// Build from config; `None` means the cache is off.
    pub fn from_config(config: &SaTokenConfig) -> Option<Arc<Self>> {
        config.grant_cache_duration().map(|ttl| {
            Arc::new(Self::new(
                ttl,
                config.grant_cache_max_entries,
                config.grant_cache_single_flight,
            ))
        })
    }

    /// 构造缓存键 | Build a cache key
    pub fn cache_key(kind: GrantKind, login_type: &str, login_id: &str) -> String {
        let mut key = String::with_capacity(2 + login_type.len() + 1 + login_id.len());
        key.push(kind.tag());
        key.push(KEY_SEP);
        key.push_str(login_type);
        key.push(KEY_SEP);
        key.push_str(login_id);
        key
    }

    /// 内部 cache key 由 login_type + login_id 组成，非攻击者可控 HTTP 输入；SipHash 无安全收益。
    /// Cache keys are composed of login_type + login_id, not attacker-controlled HTTP input; SipHash buys no safety here.
    #[inline]
    fn fnv1a(key: &str) -> usize {
        let mut hash = 0xcbf29ce484222325u64;
        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash as usize
    }

    /// 计算 key 所属分片 | Resolve the shard owning a key
    #[inline]
    fn shard_of(&self, key: &str) -> &RwLock<HashMap<String, CacheEntry>> {
        match self.shards.get(Self::fnv1a(key) & SHARD_MASK) {
            Some(s) => s,
            None => unreachable!("fnv1a masked to SHARD_COUNT"),
        }
    }

    #[inline]
    fn flight_shard(&self, key: &str) -> &tokio::sync::Mutex<FlightMap> {
        match self.flights.get(Self::fnv1a(key) & SHARD_MASK) {
            Some(s) => s,
            None => unreachable!("fnv1a masked to SHARD_COUNT"),
        }
    }

    /// 只读探测 | Read-only probe
    fn peek(&self, key: &str) -> Option<Arc<[String]>> {
        let guard = self.shard_of(key).read().ok()?;
        let entry = guard.get(key)?;
        if entry.expires_at > Instant::now() {
            Some(Arc::clone(&entry.value))
        } else {
            None
        }
    }

    /// 写入并保证容量有界 | Insert while keeping capacity bounded
    fn put(&self, key: String, value: Arc<[String]>) {
        let Ok(mut guard) = self.shard_of(&key).write() else {
            return;
        };
        let now = Instant::now();

        if guard.len() >= self.max_per_shard && !guard.contains_key(&key) {
            guard.retain(|_, entry| entry.expires_at > now);

            if guard.len() >= self.max_per_shard {
                let victim = guard
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(k, _)| k.clone());
                if let Some(victim) = victim {
                    guard.remove(&victim);
                }
            }
        }

        guard.insert(
            key,
            CacheEntry {
                value,
                expires_at: now + self.ttl,
            },
        );
    }

    /// 读取或加载 | Get or load
    pub async fn get_or_load<F, Fut>(&self, key: String, loader: F) -> SaTokenResult<Arc<[String]>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = SaTokenResult<Vec<String>>>,
    {
        if let Some(hit) = self.peek(&key) {
            return Ok(hit);
        }

        if !self.single_flight {
            let value: Arc<[String]> = loader().await?.into();
            self.put(key, Arc::clone(&value));
            return Ok(value);
        }

        let gate = {
            let mut flights = self.flight_shard(&key).lock().await;
            Arc::clone(
                flights
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _permit = gate.lock().await;

        if let Some(hit) = self.peek(&key) {
            self.release_flight(&key).await;
            return Ok(hit);
        }

        match loader().await {
            Ok(list) => {
                let value: Arc<[String]> = list.into();
                self.put(key.clone(), Arc::clone(&value));
                self.release_flight(&key).await;
                Ok(value)
            }
            Err(err) => {
                self.release_flight(&key).await;
                Err(err)
            }
        }
    }

    /// 移除门闩表中的条目 | Drop the gate entry
    async fn release_flight(&self, key: &str) {
        self.flight_shard(key).lock().await.remove(key);
    }

    /// 失效单个键 | Invalidate one key
    pub fn invalidate(&self, key: &str) {
        if let Ok(mut guard) = self.shard_of(key).write() {
            guard.remove(key);
        }
    }

    /// 失效某账号在某体系下的权限与角色两条缓存。
    /// Invalidate both the permission and role entries of an account.
    pub fn invalidate_account(&self, login_type: &str, login_id: &str) {
        self.invalidate(&Self::cache_key(
            GrantKind::Permission,
            login_type,
            login_id,
        ));
        self.invalidate(&Self::cache_key(GrantKind::Role, login_type, login_id));
    }

    /// 清空全部分片 | Clear every shard
    pub fn clear(&self) {
        for shard in self.shards.iter() {
            if let Ok(mut guard) = shard.write() {
                guard.clear();
            }
        }
    }

    /// 当前条目总数（诊断用）| Total entry count for diagnostics
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.read().ok().map(|g| g.len()))
            .sum()
    }

    /// 是否为空 | Whether the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
