import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'zuit',
  tagline:
    'See what\'s wrong with your code — across five quality dimensions, in one command, deterministically.',
  favicon: 'img/logo.svg',

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  markdown: {
    mermaid: true,
  },

  // Set the production url of your site here
  url: 'https://shubhamkaushal765.github.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/zuit/',

  // GitHub pages deployment config.
  organizationName: 'shubhamkaushal765',
  projectName: 'zuit',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Load Inter via preconnect + parallel stylesheet fetch rather than CSS
  // `@import`, which would block CSSOM construction during initial paint.
  headTags: [
    {
      tagName: 'link',
      attributes: {rel: 'preconnect', href: 'https://fonts.googleapis.com'},
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossorigin: 'anonymous',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'stylesheet',
        href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap',
      },
    },
  ],

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  themes: ['@docusaurus/theme-mermaid'],

  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/shubhamkaushal765/zuit/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Replace with your project's social card
    image: 'img/docusaurus-social-card.jpg',
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'zuit',
      logo: {
        alt: 'zuit Logo',
        src: 'img/logo.svg',
        srcDark: 'img/logo-dark.svg',
      },
      items: [
        {to: '/quickstart', label: 'Docs', position: 'left'},
        {to: '/rules/', label: 'Rules', position: 'left'},
        {
          href: 'https://github.com/shubhamkaushal765/zuit',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      copyright: `Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['rust', 'toml', 'bash', 'json', 'python'],
    },
    mermaid: {
      theme: {
        light: 'default',
        dark: 'dark',
      },
      options: {
        themeVariables: {
          /* Light mermaid theme — echoes the 60-30-10 palette */
          primaryColor:        '#1a4480',  /* --cl-accent-primary */
          primaryTextColor:    '#ffffff',  /* --cl-text-inverse */
          primaryBorderColor:  '#163c6e',  /* --cl-accent-primary-hover */
          lineColor:           '#6b7890',  /* --zuit-slate-500 */
          secondaryColor:      '#f1f4f9',  /* --cl-surface-code */
          tertiaryColor:       '#eef2f8',  /* --cl-surface-card */
          edgeLabelBackground: '#ffffff',  /* --cl-bg-default */
          clusterBkg:          '#eef2f8',  /* --cl-surface-card */
          titleColor:          '#111827',  /* --cl-text-primary */
          nodeBorder:          '#1a4480',  /* --cl-accent-primary */
          mainBkg:             '#f1f4f9',  /* --cl-surface-code */
        },
      },
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
