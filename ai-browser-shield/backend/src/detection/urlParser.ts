import { ValidationError } from '../errors';
import { URL_TYPE_SKIP_SCHEMES } from '../config/constants';
import { isIpv4, isIpv6, isLoopbackOrLocalhost, isPrivateIp } from '../utils/ip';
import { getRegistrableDomain, hostnameToUnicode, normalizeUrl, safeDecodeUrl, truncateForAi } from '../utils/url';
import type { ParsedUrlResult, UrlType } from '../types/scan.types';

const NORMAL_PROTOCOLS = new Set(['http:', 'https:', 'ftp:', 'sftp:', 'ws:', 'wss:', 'file:', 'data:', 'blob:']);

const toInternalUrl = (rawUrl: string, protocol: string, reason: string): ParsedUrlResult => ({
  originalUrl: rawUrl,
  aiSafeUrl: rawUrl,
  normalizedUrl: rawUrl,
  truncatedForAi: false,
  urlType: 'browser_internal',
  hostname: '',
  hostnameUnicode: '',
  domain: '',
  path: '',
  queryParams: {},
  port: '',
  protocol,
  isInternal: true,
  skip: true,
  skipReason: reason,
  notes: [reason],
  hasCredentials: false,
  decodedUrl: rawUrl
});

const determineUrlType = (protocol: string, hostname: string, hostnameUnicode: string): UrlType => {
  if (protocol === 'file:') {
    return 'file';
  }
  if (protocol === 'data:') {
    return 'data';
  }
  if (protocol === 'blob:') {
    return 'blob';
  }
  if (['ftp:', 'sftp:', 'ws:', 'wss:'].includes(protocol)) {
    return 'ftp';
  }
  if (isLoopbackOrLocalhost(hostname) || hostname === 'intranet') {
    return 'localhost';
  }
  if (isPrivateIp(hostname)) {
    return 'private_ip';
  }
  if (isIpv4(hostname) || isIpv6(hostname.replace(/^\[|\]$/g, ''))) {
    return 'ip_hostname';
  }
  if (hostname !== hostnameUnicode) {
    return 'idn';
  }
  return 'standard';
};

export const parseAndNormalizeUrl = (rawUrl: string): ParsedUrlResult => {
  if (typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    throw new ValidationError('url is required');
  }

  const normalizedInput = normalizeUrl(safeDecodeUrl(rawUrl));
  if (normalizedInput === 'about:blank' || normalizedInput === 'about:newtab') {
    return toInternalUrl(rawUrl, 'about:', 'browser_internal');
  }
  if (URL_TYPE_SKIP_SCHEMES.some((scheme) => normalizedInput.startsWith(scheme))) {
    return toInternalUrl(rawUrl, normalizedInput.split(':')[0] ? `${normalizedInput.split(':')[0]}:` : '', 'browser_internal');
  }
  if (normalizedInput === 'http://.' || normalizedInput === 'https://.') {
    throw new ValidationError('invalid url');
  }

  if (normalizedInput.startsWith('blob:')) {
    const target = normalizedInput.slice(5);
    const parsedBlob = parseAndNormalizeUrl(target);
    return {
      ...parsedBlob,
      originalUrl: rawUrl,
      normalizedUrl: target,
      urlType: 'blob',
      extractedBlobOrigin: target,
      notes: [...parsedBlob.notes, 'blob_origin_extracted'],
      protocol: 'blob:'
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedInput);
  } catch {
    throw new ValidationError('invalid url');
  }

  if (!NORMAL_PROTOCOLS.has(parsed.protocol)) {
    throw new ValidationError('unsupported protocol');
  }

  const safeHref = parsed.protocol === 'file:' || parsed.protocol === 'data:' ? normalizedInput : encodeURI(parsed.href);
  const aiValue = truncateForAi(safeHref);
  const hostnameUnicode = hostnameToUnicode(parsed.hostname);
  const urlType = determineUrlType(parsed.protocol, parsed.hostname, hostnameUnicode);
  const noTldInternal = parsed.hostname.length > 0 && !parsed.hostname.includes('.') && urlType === 'standard';
  const isInternal = noTldInternal || urlType === 'localhost' || urlType === 'private_ip';
  const queryParams = Object.fromEntries(parsed.searchParams.entries());

  return {
    originalUrl: rawUrl,
    aiSafeUrl: aiValue.value,
    normalizedUrl: safeHref,
    truncatedForAi: aiValue.truncated,
    urlType: noTldInternal ? 'internal' : urlType,
    hostname: parsed.hostname,
    hostnameUnicode,
    domain: parsed.hostname.length === 0 ? '' : (noTldInternal ? parsed.hostname : getRegistrableDomain(hostnameUnicode)),
    path: parsed.pathname || '/',
    queryParams,
    port: parsed.port,
    protocol: parsed.protocol,
    isInternal,
    skip: false,
    notes: [
      ...(parsed.protocol === 'file:' ? ['local_file'] : []),
      ...(parsed.protocol === 'data:' ? ['data_url'] : []),
      ...((parsed.username || parsed.password) ? ['credential_in_url'] : []),
      ...(noTldInternal ? ['internal_hostname'] : [])
    ],
    hasCredentials: Boolean(parsed.username || parsed.password),
    decodedUrl: normalizedInput
  };
};
