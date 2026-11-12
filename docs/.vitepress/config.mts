import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(defineConfig({
  title: 'valkyrie-saml-bridge',
  description: 'A SAML 2.0 identity provider for apps that only accept SAML logins, backed by an OIDC provider.',
  lang: 'en-US',
  cleanUrls: true,
  sitemap: {
    hostname: 'https://samlbridge.liesel.dev',
  },
  themeConfig: {
    nav: [
      { text: 'Configuration', link: '/configuration' },
      { text: 'SSO', link: '/sso' },
      { text: 'Flows', link: '/flows' },
      { text: 'CLI', link: '/cli' },
      { text: 'Docker', link: '/docker' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Configuration', link: '/configuration' },
          { text: 'SSO', link: '/sso' },
          { text: 'Login flows', link: '/flows' },
          { text: 'CLI', link: '/cli' },
          { text: 'Docker', link: '/docker' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/ValkyrieID/Valkyrie-saml-bridge' },
    ],
  },
}))
