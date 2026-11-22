import { createRequire } from 'node:module';

export const VERSION = (createRequire(import.meta.url)('../package.json') as { version: string }).version;
export const USER_AGENT = `fortis-healthcheck/${VERSION} (+https://github.com/Fortis-Tools/healthcheck)`;
