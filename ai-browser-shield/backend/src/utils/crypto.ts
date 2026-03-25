import { createHash, createHmac } from 'node:crypto';

/**
 * Computes a SHA-256 hex digest.
 */
export const sha256 = (value: string): string =>
  createHash('sha256').update(value).digest('hex');

/**
 * Computes an MD5 hex digest.
 */
export const md5 = (value: string): string =>
  createHash('md5').update(value).digest('hex');

/**
 * Computes an HMAC SHA-256 hex digest.
 */
export const hmacSha256 = (secret: string, value: string): string =>
  createHmac('sha256', secret).update(value).digest('hex');

/**
 * Converts a URL into a privacy-safe token for local persistence.
 */
export const hashUrlForStorage = (value: string): string =>
  `hash:${sha256(value)}`;
