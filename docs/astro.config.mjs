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
