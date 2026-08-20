import { defineConfig } from 'vitepress'

const enSidebar = [
  {
    text: 'Getting started',
    items: [
      { text: 'Home', link: '/' },
      { text: 'Quick start', link: '/guide/quick-start' },
      { text: 'Migrate to 0.2', link: '/guide/migration-0.2' },
      { text: 'Multi-account', link: '/guide/multi-account' },
    ],
  },
  {
    text: 'Basics',
    items: [
      { text: 'StpUtil', link: '/guide/stp-util' },
      { text: 'Permissions and macros', link: '/guide/permission-matching' },
      { text: 'Event listeners', link: '/guide/event-listener' },
      { text: 'Path auth', link: '/guide/path-auth' },
      { text: 'Token styles', link: '/guide/token-styles' },
    ],
  },
  {
    text: 'Advanced',
    items: [
      { text: 'JWT', link: '/guide/jwt' },
      { text: 'OAuth2', link: '/guide/oauth2' },
      { text: 'Security features', link: '/guide/security-features' },
      { text: 'WebSocket auth', link: '/guide/websocket-auth' },
      { text: 'Online users', link: '/guide/online-user-management' },
      { text: 'Distributed session', link: '/guide/distributed-session' },
      { text: 'SSO', link: '/guide/sso' },
      { text: 'Framework integration', link: '/guide/framework-integration' },
    ],
  },
  {
    text: 'Reference',
    items: [
      { text: 'Storage', link: '/guide/storage' },
      { text: 'Adapters', link: '/guide/adapter' },
      { text: 'Errors', link: '/reference/error-reference' },
    ],
  },
]

const zhSidebar = [
  {
    text: '快速入门',
    items: [
      { text: '首页', link: '/zh/' },
      { text: '快速入门', link: '/zh/guide/quick-start' },
      { text: '迁移到 0.2', link: '/zh/guide/migration-0.2' },
      { text: '多账号与终端', link: '/zh/guide/multi-account' },
    ],
  },
  {
    text: '基础',
    items: [
      { text: 'StpUtil', link: '/zh/guide/stp-util' },
      { text: '权限匹配与宏', link: '/zh/guide/permission-matching' },
      { text: '事件监听', link: '/zh/guide/event-listener' },
      { text: '路径鉴权', link: '/zh/guide/path-auth' },
      { text: 'Token 风格', link: '/zh/guide/token-styles' },
    ],
  },
  {
    text: '进阶',
    items: [
      { text: 'JWT', link: '/zh/guide/jwt' },
      { text: 'OAuth2', link: '/zh/guide/oauth2' },
      { text: '安全特性', link: '/zh/guide/security-features' },
      { text: 'WebSocket 认证', link: '/zh/guide/websocket-auth' },
      { text: '在线用户', link: '/zh/guide/online-user-management' },
      { text: '分布式 Session', link: '/zh/guide/distributed-session' },
      { text: 'SSO', link: '/zh/guide/sso' },
      { text: '框架集成', link: '/zh/guide/framework-integration' },
    ],
  },
  {
    text: '参考',
    items: [
      { text: '存储', link: '/zh/guide/storage' },
      { text: '适配器', link: '/zh/guide/adapter' },
      { text: '错误', link: '/zh/reference/error-reference' },
    ],
  },
]

export default defineConfig({
  title: 'sa-token-rust',
  description: 'Authentication and authorization for Rust',
  base: '/sa-token-rust/',

  head: [],

  locales: {
    root: {
      label: 'English',
      lang: 'en-US',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'Quick start', link: '/guide/quick-start' },
          { text: 'Guide', link: '/guide/stp-util' },
          { text: 'GitHub', link: 'https://github.com/sa-tokens/sa-token-rust' },
        ],
        sidebar: enSidebar,
        editLink: {
          pattern: 'https://github.com/sa-tokens/sa-token-rust/edit/main/doc/:path',
        },
        footer: { message: 'MIT OR Apache-2.0' },
      },
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      themeConfig: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: '快速入门', link: '/zh/guide/quick-start' },
          { text: '指南', link: '/zh/guide/stp-util' },
          { text: 'GitHub', link: 'https://github.com/sa-tokens/sa-token-rust' },
        ],
        sidebar: zhSidebar,
        editLink: {
          pattern: 'https://github.com/sa-tokens/sa-token-rust/edit/main/doc/:path',
        },
        footer: { message: 'MIT OR Apache-2.0' },
      },
    },
  },

  themeConfig: {
    logo: false,
    search: {
      provider: 'local',
      options: {
        locales: {
          root: {
            translations: {
              button: { buttonText: 'Search' },
            },
          },
          zh: {
            translations: {
              button: { buttonText: '搜索' },
            },
          },
        },
      },
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/sa-tokens/sa-token-rust' },
    ],
  },

  markdown: {
    lineNumbers: true,
  },

  vite: {
    assetsInclude: ['**/*.JPG', '**/*.jpg', '**/*.jpeg', '**/*.png'],
  },
})
