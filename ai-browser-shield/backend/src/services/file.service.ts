import { prisma } from '../db/client';
import { analyzeWithGemini } from './ai.service';
import { checkFileSafety, getExtension } from '../detection/fileChecker';
import { md5, sha256 } from '../utils/crypto';
import { parseAndNormalizeUrl } from '../detection/urlParser';
import { logger } from '../utils/logger';

export interface FileScanInput {
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sourceUrl: string;
  base64Content?: string;
  chromeDownloadId?: string;
  sessionId?: string;
  buffer?: Buffer;
  sha256Hash?: string;
  userGeminiKey?: string;
}

export const scanFile = async (input: FileScanInput) => {
  const started = Date.now();
  const extension = getExtension(input.filename);
  const parsedUrl = parseAndNormalizeUrl(input.sourceUrl);
  const fileSampleBase64 = input.buffer ? input.buffer.subarray(0, Math.min(input.buffer.length, 8192)).toString('base64') : input.base64Content?.slice(0, 8192);

  if (parsedUrl.urlType === 'localhost') {
    return {
      verdict: 'SAFE',
      confidence: 0.95,
      explanation: 'Localhost download detected and treated as internal.',
      indicators: ['localhost_source'],
      recommended_action: 'allow',
      fileScanId: '',
      processedMs: Date.now() - started
    };
  }

  const contentHash = input.sha256Hash ?? (input.buffer ? sha256(input.buffer.toString('base64')) : input.base64Content ? sha256(input.base64Content) : sha256(`${input.filename}:${input.mimeType}:${input.sizeBytes}`));
  let knownBad: Awaited<ReturnType<typeof prisma.maliciousFile.findUnique>> | null = null;
  try {
    knownBad = await prisma.maliciousFile.findUnique({ where: { sha256: contentHash } });
  } catch (error) {
    logger.warn({ err: error }, 'malicious file lookup failed');
  }

  if (knownBad) {
    let fileScanId = '';
    try {
      const fileScan = await prisma.fileScan.create({
        data: {
          filename: input.filename,
          extension,
          mimeType: input.mimeType,
          sizeBytes: BigInt(input.sizeBytes),
          sourceUrl: input.sourceUrl,
          sourceDomain: parsedUrl.domain,
          verdict: 'MALICIOUS',
          confidence: 1,
          aiExplanation: 'Known malicious file hash match.',
          indicators: { indicators: ['known_malicious_hash'] },
          recommendedAction: 'quarantine',
          chromeDownloadId: input.chromeDownloadId
        }
      });
      fileScanId = fileScan.id;
    } catch (error) {
      logger.warn({ err: error }, 'file scan write failed during known-bad match');
    }
    return {
      verdict: 'MALICIOUS',
      confidence: 1,
      explanation: 'Known malicious file hash match.',
      indicators: ['known_malicious_hash'],
      recommended_action: 'quarantine',
      fileScanId,
      processedMs: Date.now() - started
    };
  }

  const fileCheck = checkFileSafety({
    filename: input.filename,
    mimeType: input.mimeType,
    sizeBytes: input.sizeBytes
  });

  const aiAssessment = await analyzeWithGemini({
    url: input.sourceUrl,
    hostname: parsedUrl.hostnameUnicode,
    path: parsedUrl.path,
    queryParams: parsedUrl.queryParams,
    heuristicScore: fileCheck.riskScore,
    heuristicSignals: {
      typosquat: 0,
      suspiciousTLD: 0,
      ipAsHostname: 0,
      longSubdomains: 0,
      suspiciousKeywords: 0,
      encodedChars: 0,
      pathEntropy: 0,
      portAnomaly: 0,
      credentialInUrl: 0,
      idnHomoglyph: 0,
      excessiveDots: 0,
      numericSubdomain: 0,
      tldMismatch: 0,
      repeatingSegments: 0,
      queryParamCount: 0,
      redirectParam: 0
    },
    domainReputation: {
      riskScore: 0,
      reportCount: 0,
      trustScore: 50,
      is_whitelisted: false
    },
    fileData: {
      filename: input.filename,
      mimeType: input.mimeType,
      sizeBytes: input.sizeBytes,
      extension,
      fileSampleBase64
    },
    urlType: parsedUrl.urlType,
    domain: parsedUrl.domain,
    userGeminiKey: input.userGeminiKey
  });

  const verdict = aiAssessment.riskLevel === 'CRITICAL' || aiAssessment.riskLevel === 'HIGH'
    ? 'MALICIOUS'
    : aiAssessment.riskLevel === 'MEDIUM'
      ? 'SUSPICIOUS'
      : 'SAFE';

  let fileScanId = '';
  try {
    const fileScan = await prisma.fileScan.create({
      data: {
        filename: input.filename,
        extension,
        mimeType: input.mimeType,
        sizeBytes: BigInt(input.sizeBytes),
        sourceUrl: input.sourceUrl,
        sourceDomain: parsedUrl.domain,
        verdict,
        confidence: aiAssessment.confidence,
        aiExplanation: aiAssessment.explanation,
        indicators: { indicators: Array.from(new Set([...fileCheck.indicators, ...aiAssessment.keyIndicators])) },
        recommendedAction: aiAssessment.recommendedAction,
        chromeDownloadId: input.chromeDownloadId
      }
    });
    fileScanId = fileScan.id;
  } catch (error) {
    logger.warn({ err: error }, 'file scan write failed');
  }

  try {
    await prisma.downloadRecord.upsert({
      where: { chromeDownloadId: input.chromeDownloadId ?? `${contentHash.slice(0, 16)}-${input.filename}` },
      update: {
        url: input.sourceUrl,
        filename: input.filename,
        mimeType: input.mimeType,
        sizeBytes: BigInt(input.sizeBytes),
        riskLevel: aiAssessment.riskLevel,
        aiVerdict: aiAssessment.explanation,
        fileScanId: fileScanId || null,
        sessionId: input.sessionId
      },
      create: {
        chromeDownloadId: input.chromeDownloadId ?? `${contentHash.slice(0, 16)}-${input.filename}`,
        url: input.sourceUrl,
        filename: input.filename,
        mimeType: input.mimeType,
        sizeBytes: BigInt(input.sizeBytes),
        status: verdict === 'SAFE' ? 'pending' : 'flagged',
        riskLevel: aiAssessment.riskLevel,
        aiVerdict: aiAssessment.explanation,
        fileScanId: fileScanId || null,
        sessionId: input.sessionId
      }
    });
  } catch (error) {
    logger.warn({ err: error }, 'download record write failed');
  }

  return {
    verdict,
    confidence: aiAssessment.confidence,
    explanation: aiAssessment.explanation,
    indicators: Array.from(new Set([...fileCheck.indicators, ...aiAssessment.keyIndicators])),
    recommended_action: aiAssessment.recommendedAction,
    fileScanId,
    processedMs: Date.now() - started,
    sha256: contentHash,
    md5: input.buffer ? md5(input.buffer.toString('base64')) : input.base64Content ? md5(input.base64Content) : ''
  };
};
