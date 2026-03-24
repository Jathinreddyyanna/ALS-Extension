import { domainToUnicode, domainToASCII } from 'node:url';
import { env } from '../config';

export const normalizeUrl = (url: string): string => url.trim();

export const truncateForAi = (url: string): { value: string; truncated: boolean } => {
  if (url.length <= env.MAX_URL_LENGTH) {
    return { value: url, truncated: false };
  }
  return { value: url.slice(0, env.MAX_URL_LENGTH), truncated: true };
};

export const safeDecodeUrl = (url: string): string => {
  try {
    return decodeURIComponent(url);
  } catch {
    return url;
  }
};

export const hostnameToUnicode = (hostname: string): string => {
  try {
    return domainToUnicode(hostname);
  } catch {
    return hostname;
  }
};

export const hostnameToAscii = (hostname: string): string => {
  try {
    return domainToASCII(hostname);
  } catch {
    return hostname;
  }
};

export const getRegistrableDomain = (hostname: string): string => {
  const labels = hostname.replace(/^\[|\]$/g, '').split('.').filter(Boolean);
  if (labels.length <= 2) {
    return labels.join('.');
  }
  const multiPartTlds = [
    'co.in', 'gov.in', 'net.in', 'org.in', 'ac.in',
    'bank.in', 'fin.in', 'nic.in', 'edu.in', 'res.in',
    'co.uk', 'ac.uk', 'org.uk', 'com.au', 'co.nz', 'com.ro'
  ];
  const tail = labels.slice(-2).join('.');
  if (multiPartTlds.includes(tail)) {
    return labels.slice(-3).join('.');
  }
  return labels.slice(-2).join('.');
};
