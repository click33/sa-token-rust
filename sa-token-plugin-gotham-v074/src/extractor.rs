use crate::wrapper::{LoginIdWrapper, TokenValueWrapper};
use gotham::state::State;
use sa_token_core::token::TokenValue;

/// 中文: 必填 Token 提取器（从 Gotham 状态获取 Token），允许为空以适配中间件注入流程
/// English: Required token extractor (reads token from Gotham state), returns Option for middleware compatibility
#[derive(Clone)]
pub struct SaTokenExtractor(pub Option<TokenValue>);

impl SaTokenExtractor {
    /// 中文: 从 State 中读取 TokenValue（中间件写入）
    /// English: Reads TokenValue stored in State by middleware
    pub fn from_state(state: &State) -> Self {
        let token = state
            .try_borrow::<TokenValueWrapper>()
            .map(|wrapper| wrapper.0.clone());
        SaTokenExtractor(token)
    }
}

/// 中文: 可选 Token 提取器（不存在时返回 None）
/// English: Optional token extractor returning None when token is missing
#[derive(Clone)]
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    /// 中文: 尝试从 State 获取 TokenValue，若不存在则返回 None
    /// English: Attempts to fetch TokenValue from State, returns None when absent
    pub fn from_state(state: &State) -> Self {
        let token = state
            .try_borrow::<TokenValueWrapper>()
            .map(|wrapper| wrapper.0.clone());
        OptionalSaTokenExtractor(token)
    }
}

/// 中文: 登录 ID 提取器，从 State 中读取当前登录用户 ID
/// English: Login ID extractor that reads current user's ID from State
#[derive(Clone)]
pub struct LoginIdExtractor(pub Option<String>);

impl LoginIdExtractor {
    /// 中文: 获取登录 ID（若中间件未设置则为 None）
    /// English: Retrieves login ID from State, None when middleware did not populate it
    pub fn from_state(state: &State) -> Self {
        let login_id = state
            .try_borrow::<LoginIdWrapper>()
            .map(|wrapper| wrapper.0.clone());
        LoginIdExtractor(login_id)
    }
}
