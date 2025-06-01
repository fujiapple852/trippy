import { defineCollection } from 'astro:content';
import { docsSchema } from '@astrojs/starlight/schema';
import { docsVersionsLoader } from 'starlight-versions/loader'

export const collections = {
    docs: defineCollection({ schema: docsSchema() }),
    versions: defineCollection({ loader: docsVersionsLoader() }),
};
