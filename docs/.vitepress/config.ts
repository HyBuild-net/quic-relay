import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'QUIC Relay',
  description: 'Reverse proxy for Hytale servers - route multiple Hytale servers through one IP using SNI-based QUIC routing',

  base: '/quic-relay/',
  cleanUrls: true,

  head: [
    ['link', { rel: 'icon', href: '/quic-relay/favicon.ico' }],
    ['meta', { name: 'google-site-verification', content: '-T2K0pWwX_CIpTMvP-RrEmr0nCenG4Nhw1YIl5NcjDQ' }],
    ['meta', { property: 'og:site_name', content: 'QUIC Relay' }],
    ['meta', { property: 'og:locale', content: 'en' }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
    ['meta', { name: 'robots', content: 'index, follow' }]
  ],

  themeConfig: {
    logo: {
      src: '/logo.png',
      width: 140,
      height: 140
    },
    siteTitle: false,

    nav: [
      { text: 'Documentation', link: '/getting-started' },
      { text: 'GitHub', link: 'https://github.com/HyBuildNet/quic-relay' }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Getting Started', link: '/getting-started' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'Handlers', link: '/handlers' },
          { text: 'Configuration', link: '/configuration' },
          { text: 'TLS Termination', link: '/tls-termination' }
        ]
      }
    ],

    outline: {
      level: [2, 3]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/HyBuildNet/quic-relay' }
    ],

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/HyBuildNet/quic-relay/edit/master/docs/:path',
      text: 'Edit this page on GitHub'
    }
  }
})
