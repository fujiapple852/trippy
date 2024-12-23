import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
    site: 'https://trippy.rs',
	integrations: [
		starlight({
			title: 'Trippy',
            customCss: [
              // Relative path to your custom CSS file
              './src/styles/custom.css',
            ],
             editLink: {
               baseUrl: 'https://github.com/fujiapple852/trippy/edit/master/docs/',
             },
            logo: {
              light: './src/assets/Trippy-Horizontal.png',
              dark: './src/assets/Trippy-Horizontal-DarkMode.png',
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
			social: {
				'github': 'https://github.com/fujiapple852/trippy',
				'zulip': 'https://trippy.zulipchat.com',
				'matrix': 'https://matrix.to/#/#trippy-dev:matrix.org',
				'x.com': 'https://x.com/FujiApple852v2',
			},
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
