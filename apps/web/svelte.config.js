import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const apiOrigin = process.env.PUBLIC_CAIRN_API_ORIGIN || 'http://localhost:8080';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csp: {
      mode: 'auto',
      directives: {
        'default-src': ['self'],
        'script-src': ['self'],
        'style-src': ['self'],
        'img-src': ['self', 'data:'],
        'font-src': ['self', 'data:'],
        'connect-src': ['self', apiOrigin],
        'object-src': ['none'],
        'base-uri': ['none'],
        'frame-ancestors': ['none'],
        'form-action': ['self']
      }
    }
  }
};

export default config;
