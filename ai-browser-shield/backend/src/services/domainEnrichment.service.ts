import { lookup } from 'node:dns/promises';
import { connect as tlsConnect } from 'node:tls';
import { env } from '../config';
import { cacheGetJSON, cacheSetJSON } from './cache.service';
import { runResilientTask } from './resilience.service';
import { logger } from '../utils/logger';

export interface DomainEnrichment {
  domainAgeDays: number | null;
  dnsStatus: 'resolved' | 'nxdomain' | 'unknown';
  dnsFastFluxRisk: boolean;
  sslStatus: 'valid' | 'self_signed' | 'hostname_mismatch' | 'invalid' | 'unknown';
  sslIssuer?: string;
  sslTrusted: boolean;
  asnReputation: 'trusted' | 'neutral' | 'cheap_hosting';
  positives: string[];
  warnings: string[];
}

const DEFAULT_ENRICHMENT: DomainEnrichment = {
  domainAgeDays: null,
  dnsStatus: 'unknown',
  dnsFastFluxRisk: false,
  sslStatus: 'unknown',
  sslTrusted: false,
  asnReputation: 'neutral',
  positives: [],
  warnings: []
};

const CHEAP_HOSTING_SUFFIXES = [
  'vercel.app', 'netlify.app', 'github.io', 'pages.dev', 'workers.dev',
  'firebaseapp.com', 'web.app', '000webhostapp.com', 'weebly.com', 'wixsite.com'
];

const TRUSTED_SSL_ISSUERS = [
  'digicert', 'let\'s encrypt', 'google trust services', 'sectigo',
  'globalsign', 'amazon', 'cloudflare', 'go daddy', 'entrust'
];

function estimateAgeFromDomain(registeredDomain: string): number | null {
  if (registeredDomain.endsWith('.gov') || registeredDomain.endsWith('.gov.in') || registeredDomain.endsWith('.bank.in') || registeredDomain.endsWith('.bank')) {
    return 3650;
  }
  if (/(^|[-.])(new|verify|secure|login|202[4-9])([-.]|$)/i.test(registeredDomain)) {
    return 14;
  }
  return null;
}

function getAsnReputation(registeredDomain: string): DomainEnrichment['asnReputation'] {
  if (CHEAP_HOSTING_SUFFIXES.some((suffix) => registeredDomain === suffix || registeredDomain.endsWith(`.${suffix}`))) {
    return 'cheap_hosting';
  }
  return 'neutral';
}

async function resolveDnsStatus(hostname: string): Promise<Pick<DomainEnrichment, 'dnsStatus' | 'dnsFastFluxRisk'>> {
  if (env.NODE_ENV === 'test') {
    return { dnsStatus: 'unknown', dnsFastFluxRisk: false };
  }

  try {
    const result = await runResilientTask(
      () => lookup(hostname, { all: true }),
      { name: `dns:${hostname}`, retries: 1, timeoutMs: 700, baseDelayMs: 100 }
    );
    return {
      dnsStatus: result.length > 0 ? 'resolved' : 'unknown',
      dnsFastFluxRisk: result.length >= 6
    };
  } catch (error) {
    const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code?: string }).code) : '';
    return {
      dnsStatus: code === 'ENOTFOUND' ? 'nxdomain' : 'unknown',
      dnsFastFluxRisk: false
    };
  }
}

async function inspectTls(hostname: string): Promise<Pick<DomainEnrichment, 'sslStatus' | 'sslIssuer' | 'sslTrusted'>> {
  if (env.NODE_ENV === 'test') {
    return { sslStatus: 'unknown', sslTrusted: false };
  }

  try {
    return await runResilientTask(() => new Promise((resolve, reject) => {
      const socket = tlsConnect({
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 1200
      }, () => {
        try {
          const cert = socket.getPeerCertificate();
          const hostError = require('node:tls').checkServerIdentity(hostname, cert);
          const hostnameMatch = !hostError;

          const issuer = typeof cert?.issuer?.O === 'string' ? cert.issuer.O : typeof cert?.issuer?.CN === 'string' ? cert.issuer.CN : undefined;
          const subjectCn = typeof cert?.subject?.CN === 'string' ? cert.subject.CN : '';
          const issuerTrusted = issuer ? TRUSTED_SSL_ISSUERS.some((item) => issuer.toLowerCase().includes(item)) : false;
          
          const selfSigned = Boolean(issuer && subjectCn && issuer === subjectCn);
          
          const sslStatus =
            selfSigned ? 'self_signed'
              : !hostnameMatch ? 'hostname_mismatch'
                : (issuerTrusted || socket.authorized) ? 'valid'
                  : 'invalid';
          
          socket.end();
          resolve({
            sslStatus,
            sslIssuer: issuer,
            sslTrusted: (issuerTrusted || socket.authorized) && hostnameMatch && !selfSigned
          });
        } catch (error) {
          reject(error);
        }
      });
      socket.on('error', reject);
      socket.on('timeout', () => {
        socket.destroy(new Error('tls_timeout'));
      });
    }), { name: `tls:${hostname}`, retries: 0, timeoutMs: 1500 });
  } catch {
    return { sslStatus: 'unknown', sslTrusted: false };
  }
}

export async function enrichDomainSignals(input: {
  hostname: string;
  registeredDomain: string;
  isHTTPS: boolean;
  isOfficialTLD: boolean;
  reputationFirstSeen?: Date | null;
}): Promise<DomainEnrichment> {
  const cacheKey = `enrich:${input.registeredDomain}`;
  const cached = await cacheGetJSON<DomainEnrichment>(cacheKey);
  if (cached) {
    return cached;
  }

  const positives: string[] = [];
  const warnings: string[] = [];

  const [dns, tls] = await Promise.all([
    resolveDnsStatus(input.hostname),
    input.isHTTPS ? inspectTls(input.hostname) : Promise.resolve({ sslStatus: 'unknown' as const, sslTrusted: false, sslIssuer: undefined })
  ]);

  const ageFromDb = input.reputationFirstSeen ? Math.max(1, Math.round((Date.now() - input.reputationFirstSeen.getTime()) / (24 * 60 * 60 * 1000))) : null;
  const domainAgeDays = ageFromDb ?? estimateAgeFromDomain(input.registeredDomain);
  const asnReputation = getAsnReputation(input.registeredDomain);

  if (domainAgeDays !== null && domainAgeDays >= 365) positives.push('Established domain');
  if (dns.dnsStatus === 'resolved') positives.push('DNS resolved normally');
  if (tls.sslTrusted) positives.push('Trusted SSL certificate');

  if (domainAgeDays !== null && domainAgeDays < 30) warnings.push('Newly registered domain');
  if (dns.dnsStatus === 'nxdomain') warnings.push('DNS instability detected');
  if (dns.dnsFastFluxRisk) warnings.push('Fast-flux hosting pattern');
  if (tls.sslStatus === 'self_signed') warnings.push('Self-signed certificate');
  if (tls.sslStatus === 'hostname_mismatch') warnings.push('Certificate hostname mismatch');
  if (asnReputation === 'cheap_hosting' && !input.isOfficialTLD) warnings.push('Low-trust hosting provider');

  const result: DomainEnrichment = {
    domainAgeDays,
    dnsStatus: dns.dnsStatus,
    dnsFastFluxRisk: dns.dnsFastFluxRisk,
    sslStatus: tls.sslStatus,
    sslIssuer: tls.sslIssuer,
    sslTrusted: tls.sslTrusted,
    asnReputation,
    positives,
    warnings
  };

  await cacheSetJSON(cacheKey, result, 1800);
  return result;
}
