import { createHmac } from 'node:crypto';
import { env } from '../config';
import { sha256 } from './crypto';

let cachedSalt: { date: string; salt: string } | null = null;

const getIpv4Parts = (value: string): number[] | null => {
  const parts = value.split('.').map((part) => Number(part));
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? parts : null;
};

export const isIpv4 = (value: string): boolean => getIpv4Parts(value) !== null;

export const isIpv6 = (value: string): boolean => value.includes(':');

export const isLoopbackOrLocalhost = (hostname: string): boolean =>
  hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname === '::1' || hostname === '[::1]';

export const isPrivateIpv4 = (hostname: string): boolean => {
  const parts = getIpv4Parts(hostname);
  if (!parts) {
    return false;
  }
  const a = parts[0] ?? 0;
  const b = parts[1] ?? 0;
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
};

export const isPrivateIpv6 = (hostname: string): boolean => {
  const normalized = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd');
};

export const isPrivateIp = (hostname: string): boolean => isPrivateIpv4(hostname) || isPrivateIpv6(hostname);

export const getCurrentSalt = (): string => {
  const today = new Date().toISOString().slice(0, 10);
  if (cachedSalt?.date === today) {
    return cachedSalt.salt;
  }
  const salt = createHmac('sha256', env.DAILY_SALT_SECRET).update(today).digest('hex');
  cachedSalt = { date: today, salt };
  return salt;
};

export const resetDailySaltCache = (): void => {
  cachedSalt = null;
};

export const hashIp = (ip: string): string => sha256(`${ip}:${getCurrentSalt()}`);
