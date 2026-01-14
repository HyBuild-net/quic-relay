import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'QUIC Relay',
  description: 'SNI-based reverse proxy for QUIC connections',

  base: '/quic-relay/',
  cleanUrls: true,

  head: [
    ['link', { rel: 'icon', href: '/quic-relay/favicon.ico' }],
    ['meta', { name: 'google-site-verification', content: '-T2K0pWwX_CIpTMvP-RrEmr0nCenG4Nhw1YIl5NcjDQ' }]
  ],

  themeConfig: {
    nav: [
      { text: 'Documentation', link: '/getting-started' },
      { text: 'GitHub', link: 'https://github.com/HyBuild-net/quic-relay' }
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
          { text: 'Configuration', link: '/configuration' }
        ]
      }
    ],

    outline: {
      level: [2, 3]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/HyBuild-net/quic-relay' }
    ],

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/HyBuild-net/quic-relay/edit/master/docs/:path',
      text: 'Edit this page on GitHub'
    }
  }
})
