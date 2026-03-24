import type { RiskLevel } from '@/types/index';

export const riskLabels: Record<RiskLevel, { label: string; description: string; tone: string; iconLabel: string }> = {
  LOW: {
    label: 'Safe',
    description: 'This site looks safe to browse.',
    tone: 'safe',
    iconLabel: 'Protection confirmed'
  },
  MEDIUM: {
    label: 'Caution',
    description: 'Something looks unusual, so slow down and take a closer look.',
    tone: 'caution',
    iconLabel: 'Use extra caution'
  },
  HIGH: {
    label: 'Likely Threat',
    description: 'This site shows multiple warning signs and may try to trick you.',
    tone: 'danger',
    iconLabel: 'Likely unsafe site'
  },
  CRITICAL: {
    label: 'Block This',
    description: 'This site looks highly unsafe and should be avoided.',
    tone: 'critical',
    iconLabel: 'Severe threat detected'
  }
};

export const plainSignalLabels: Record<string, string> = {
  typosquat: 'Login page look-alike',
  suspiciousTLD: 'Suspicious web address ending',
  ipAsHostname: 'Direct server address used',
  longSubdomains: 'Overly long website name',
  suspiciousKeywords: 'Common scam wording',
  encodedChars: 'Hidden characters in link',
  pathEntropy: 'Random-looking web address',
  portAnomaly: 'Unusual connection port',
  credentialInUrl: 'Password included in link',
  idnHomoglyph: 'Look-alike letters detected',
  excessiveDots: 'Too many sub-addresses',
  numericSubdomain: 'Number-heavy web address',
  tldMismatch: 'Brand and domain ending do not match',
  repeatingSegments: 'Repeated link segments',
  queryParamCount: 'Too many hidden parameters',
  redirectParam: 'Link tries to redirect elsewhere',
  community_reports: 'Community reports found',
  local_file: 'Local file on your device',
  data_url: 'Embedded page data',
  credential_in_url: 'Password included in address',
  blob_origin_extracted: 'Checked the page that created this file',
  browser_internal: 'Browser internal page'
};

export const categoryLabels: Record<string, string> = {
  phishing: 'Fake login page',
  scam: 'Scam',
  malware: 'Malware',
  redirect: 'Redirect tricks',
  popup_abuse: 'Popup abuse',
  ad_abuse: 'Unwanted ads',
  piracy: 'Piracy / streaming trap',
  data_exfil: 'Data theft',
  crypto_mining: 'Crypto mining',
  clean: 'Looks clean',
  unknown: 'Needs review',
  other: 'Other'
};
