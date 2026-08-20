#!/usr/bin/env bash

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SLEEP_SECONDS="${SLEEP_SECONDS:-5}"
VERIFY="${VERIFY:-1}" # 1=发布前执行一次 workspace 校验，0=跳过
SKIP_PUBLISHED="${SKIP_PUBLISHED:-1}" # 1=已发布版本自动跳过，0=遇到已发布直接失败

publish() {
  local manifest="$1"
  local output

  echo "Publishing ${manifest}..."
  if output="$(cargo publish --manifest-path "$manifest" 2>&1)"; then
    echo "$output"
  else
    echo "$output"
    if [[ "$SKIP_PUBLISHED" == "1" ]] && [[ "$output" == *"already exists on crates.io index"* ]]; then
      echo "Skip published crate: ${manifest}"
      return 0
    fi
    echo "Publish failed: ${manifest}"
    return 1
  fi

  echo "Waiting ${SLEEP_SECONDS}s for crates.io index to update..."
  sleep "${SLEEP_SECONDS}"
}

if [[ "$VERIFY" == "1" ]]; then
  echo "Running pre-publish quality gate..."

  # 1) 格式门禁：任何未格式化的代码都不允许发布
  echo "  [1/4] cargo fmt --check"
  cargo fmt --all --manifest-path "$WORKSPACE_ROOT/Cargo.toml" -- --check

  # 2) lint 门禁（阻塞档）：panic 类 lint 暂时豁免，
  #    豁免清单 == P9/P12 的待办清单，不允许扩大
  echo "  [2/4] cargo clippy -D warnings"
  cargo clippy --workspace --all-targets \
    --manifest-path "$WORKSPACE_ROOT/Cargo.toml" -- \
    -D warnings \
    -A clippy::unwrap_used \
    -A clippy::expect_used \
    -A clippy::panic \
    -A clippy::indexing_slicing \
    -A clippy::unwrap_in_result \
    -A missing_docs \
    -A unreachable_pub \
    -A missing_debug_implementations \
    -A unused_qualifications

  # 3) 测试门禁
  echo "  [3/4] cargo test --workspace"
  cargo test --workspace --manifest-path "$WORKSPACE_ROOT/Cargo.toml"

  # 供应链审计：cargo-deny 未安装时跳过而非失败（deny.toml 属按需执行）
  if command -v cargo-deny >/dev/null 2>&1; then
    echo "  [extra] cargo deny check"
    cargo deny --manifest-path "$WORKSPACE_ROOT/Cargo.toml" check
  else
    echo "  [extra] cargo-deny not installed, skipping (install: cargo install cargo-deny --locked)"
  fi

  echo "Quality gate passed."
fi

# 发布顺序：先基础库，再版本绑定插件，最后 facade 与根包
publish "$WORKSPACE_ROOT/sa-token-adapter/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-storage-memory/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-storage-redis/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-macro/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-storage-database/Cargo.toml"
# 通用插件共享层
publish "$WORKSPACE_ROOT/sa-token-plugin-common/Cargo.toml"
# 一体化插件
publish "$WORKSPACE_ROOT/sa-token-plugin-axum/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-poem/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-tide/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-warp/Cargo.toml"

# Actix（v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web-v4/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web-v5/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web/Cargo.toml"

# Rocket（v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-rocket-v05/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-rocket/Cargo.toml"

# Salvo（v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-salvo-v079/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-salvo/Cargo.toml"

# Gotham（v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-gotham-v074/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-gotham/Cargo.toml"

# Ntex（v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-ntex-v212/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-ntex/Cargo.toml"

# Tonic gRPC 插件（须在根 facade 包之前发布，供依赖解析）
publish "$WORKSPACE_ROOT/sa-token-plugin-tonic/Cargo.toml"

# 根包
publish "$WORKSPACE_ROOT/Cargo.toml"

echo "All crates published."
