import { createHash } from 'node:crypto';

export const sha256 = (value: string): string =>
  createHash('sha256').update(value).digest('hex');

export const md5 = (value: string): string =>
  createHash('md5').update(value).digest('hex');
