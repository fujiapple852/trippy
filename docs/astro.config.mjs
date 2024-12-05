import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
    site: 'https://trippy.cli.rs',
	integrations: [
		starlight({
			title: 'Trippy',
             editLink: {
               baseUrl: 'https://github.com/fujiapple852/trippy/edit/master/docs/',
             },
            logo: {
              src: './src/assets/houston.webp',
              replacesTitle: true,
            },
			social: {
				'github': 'https://github.com/fujiapple852/trippy',
				'zulip': 'https://trippy.zulipchat.com',
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
