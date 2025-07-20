import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightVersions from 'starlight-versions'

// https://astro.build/config
export default defineConfig({
    site: 'https://trippy.rs',
    integrations: [
        starlight({
            plugins: [
              starlightVersions({
                versions: [{ slug: '0.12.2' }, { slug: '0.13.0' }],
              }),
            ],
            title: 'Trippy',
            customCss: [
              // Relative path to your custom CSS file
              './src/styles/custom.css',
            ],
             editLink: {
               baseUrl: 'https://github.com/fujiapple852/trippy/edit/master/docs/',
             },
            logo: {
              light: './src/assets/Trippy-Horizontal.svg',
              dark: './src/assets/Trippy-Horizontal-DarkMode.svg',
              replacesTitle: true,
            },
            head: [
              {
                tag: 'link',
                attrs: {
                  rel: 'apple-touch-icon',
                  href: '/apple-touch-icon.png',
                },
              },
              {
                tag: 'script',
                attrs: {
                  defer: true,
                  src: 'https://cloud.umami.is/script.js',
                  'data-website-id': '02e6fe53-a5b1-4f2a-b3e6-87124b1b276b',
                  'data-astro-rerun': true
                }
              }
            ],
            social: [
                { icon: 'github', label: 'github', href: 'https://github.com/fujiapple852/trippy' },
                { icon: 'zulip', label: 'zulip', href: 'https://trippy.zulipchat.com' },
                { icon: 'matrix', label: 'matrix', href: 'https://matrix.to/#/#trippy-dev:matrix.org' },
                { icon: 'x.com', label: 'x.com', href: 'https://x.com/FujiApple852v2' },
            ],
            sidebar: [
                {
                    label: 'Start Here',
                    autogenerate: { directory: 'start' }
                },
                {
                    label: 'Guides',
                    autogenerate: { directory: 'guides' }
                },
                {
                    label: 'Reference',
                    autogenerate: { directory: 'reference' },
                },
                {
                    label: 'Development',
                    autogenerate: { directory: 'development' },
                },
            ],
        }),
    ],
});
