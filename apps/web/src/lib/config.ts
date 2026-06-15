import { env } from '$env/dynamic/public';

export const apiOrigin = env.PUBLIC_CAIRN_API_ORIGIN || 'http://localhost:8080';
