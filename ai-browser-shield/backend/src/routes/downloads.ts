import { Router, Request, Response } from 'express'
import { prisma } from '../db/client'
import { analyzeDownload } from '../ai/gemini-integration'

const router = Router()

async function getWebsiteRiskSummary(hostname: string) {
  const domainScore = await prisma.domainScore.findUnique({
    where: { domain: hostname },
  }).catch(() => null)

  const latestThreat = await prisma.detectionEvent.findFirst({
    where: { domain: hostname, eventType: 'url_threat' },
    orderBy: { createdAt: 'desc' },
  }).catch(() => null)

  const riskScore = Math.max(domainScore?.riskScore ?? 0, latestThreat?.riskScore ?? 0)
  const riskLevel =
    riskScore >= 75 ? 'CRITICAL'
    : riskScore >= 50 ? 'HIGH'
    : riskScore >= 30 ? 'MEDIUM'
    : 'LOW'

  return {
    domain: hostname,
    riskScore,
    riskLevel,
    explanation:
      latestThreat?.aiExplanation ||
      (riskLevel === 'CRITICAL' || riskLevel === 'HIGH'
        ? 'This download originated from a website we already consider risky.'
        : riskLevel === 'MEDIUM'
          ? 'This download originated from a website with caution-level signals.'
          : 'No elevated site risk is currently recorded for this download source.'),
    reportCount: domainScore?.reportCount ?? 0,
  }
}

router.post('/intercept', async (req: Request, res: Response) => {
  try {
    const {
      filename,
      url,
      mimeType,
      fileSize,
      tabId,
    } = req.body

    if (!filename || typeof filename !== 'string' || !url || typeof url !== 'string') {
      return res.status(400).json({
        error: 'INVALID_DOWNLOAD_METADATA',
        message: 'filename and url are required',
      })
    }

    let hostname: string
    try {
      hostname = new URL(url).hostname
    } catch {
      return res.status(400).json({
        error: 'INVALID_DOWNLOAD_METADATA',
        message: 'url must be a valid URL',
      })
    }

    const safeMimeType = typeof mimeType === 'string' && mimeType.trim() ? mimeType : 'application/octet-stream'
    const safeFileSize = typeof fileSize === 'number' && Number.isFinite(fileSize) && fileSize >= 0 ? fileSize : 0
    const safeTabId = typeof tabId === 'number' && Number.isInteger(tabId) ? tabId : -1

    const lastDotIndex = filename.lastIndexOf('.')
    const extension = lastDotIndex >= 0 ? filename.substring(lastDotIndex) : ''
    const siteRisk = await getWebsiteRiskSummary(hostname)

    const download = await prisma.downloadRecord.create({
      data: {
        filename,
        extension,
        mimeType: safeMimeType,
        fileSize: safeFileSize,
        sourceUrl: url,
        sourceHostname: hostname,
        status: 'PENDING_REVIEW',
        approvalStatus: 'WAITING_USER',
        tabId: safeTabId,
      },
    }).catch((err) => {
      console.warn('[Zero Trust] DownloadRecord create failed, falling back to non-blocking mode:', err)
      return null
    })

    if (!download) {
      return res.status(202).json({
        blocked: false,
        downloadId: null,
        requiresApproval: false,
        message: 'Download review service is temporarily unavailable. Falling back to local checks.',
        siteRisk,
      })
    }

    console.log(`[Zero Trust] Download queued for review: ${download.id} - ${filename}`)

    analyzeDownloadWithGemini(download.id, filename, extension, safeMimeType).catch((err) =>
      console.error('[Zero Trust] AI enqueue error:', err)
    )

    res.json({
      blocked: false,
      downloadId: download.id,
      requiresApproval: true,
      message: 'Download review required. User verification requested.',
      siteRisk,
    })
  } catch (error) {
    console.error('[Zero Trust] Intercept failed:', error)
    res.status(500).json({ error: 'Download interception failed' })
  }
})

router.get('/:downloadId/approval', async (req: Request, res: Response) => {
  try {
    const { downloadId } = req.params

    const download = await prisma.downloadRecord.findUnique({
      where: { id: downloadId },
    })

    if (!download) {
      return res.status(404).json({ error: 'DOWNLOAD_NOT_FOUND', message: 'Download not found' })
    }

    const maxAgeMs = 5 * 60 * 1000
    const ageMs = Date.now() - download.createdAt.getTime()
    if (ageMs > maxAgeMs) {
      return res.status(410).json({
        error: 'APPROVAL_EXPIRED',
        message: 'The approval window for this download has expired.',
      })
    }

    const aiAnalysis = download.aiAnalysis
      ? JSON.parse(download.aiAnalysis as string)
      : null
    const siteRisk = await getWebsiteRiskSummary(download.sourceHostname)

    const databaseMatch = await checkFileDatabase(download)

    const approvalRequest = {
      downloadId: download.id,
      filename: download.filename,
      size: download.fileSize,
      sourceUrl: download.sourceUrl,

      aiVerdict: aiAnalysis || {
        verdict: 'SUSPICIOUS',
        confidence: 0.5,
        score: 50,
        explanation: 'File analysis in progress. Please wait...',
        indicators: [],
        recommendations: [
          'Only approve if you trust the source',
          'Verify the file is expected from this website',
        ],
      },

      databaseMatch,
      siteRisk,

      userOptions: {
        approve: `Download "${download.filename}"`,
        reject: `Block "${download.filename}"`,
        quarantine: 'Quarantine for analysis',
      },

      expiresIn: 5 * 60 * 1000,
    }

    res.json(approvalRequest)
  } catch (error) {
    console.error('[Zero Trust] Get approval failed:', error)
    res.status(500).json({ error: 'Could not get approval data' })
  }
})

router.post('/:downloadId/approve', async (req: Request, res: Response) => {
  try {
    const { downloadId } = req.params
    const { reason } = req.body

    const existing = await prisma.downloadRecord.findUnique({
      where: { id: downloadId },
    })

    if (!existing) {
      return res.status(404).json({ error: 'DOWNLOAD_NOT_FOUND', message: 'Download not found' })
    }

    const download = await prisma.downloadRecord.update({
      where: { id: downloadId },
      data: {
        status: 'APPROVED',
        approvalStatus: 'USER_APPROVED',
        userAction: 'APPROVED',
        userActionReason: reason || 'User approved download',
        userActionTime: new Date(),
      },
    })

    console.log(`[Zero Trust] User APPROVED: ${download.filename}`)

    await prisma.downloadAudit.create({
      data: {
        downloadId: download.id,
        action: 'USER_APPROVED',
        reason: reason || 'User approved download',
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || '',
      },
    })

    res.json({
      approved: true,
      allowDownload: true,
      message: `Download approved. File: ${download.filename}`,
    })
  } catch (error) {
    console.error('[Zero Trust] Approve failed:', error)
    res.status(500).json({ error: 'Approval failed' })
  }
})

router.post('/:downloadId/reject', async (req: Request, res: Response) => {
  try {
    const { downloadId } = req.params
    const { reason } = req.body

    const existing = await prisma.downloadRecord.findUnique({
      where: { id: downloadId },
    })

    if (!existing) {
      return res.status(404).json({ error: 'DOWNLOAD_NOT_FOUND', message: 'Download not found' })
    }

    const download = await prisma.downloadRecord.update({
      where: { id: downloadId },
      data: {
        status: 'REJECTED',
        approvalStatus: 'USER_REJECTED',
        userAction: 'REJECTED',
        userActionReason: reason || 'User blocked download',
        userActionTime: new Date(),
      },
    })

    console.log(`[Zero Trust] User REJECTED: ${download.filename}`)

    await prisma.downloadAudit.create({
      data: {
        downloadId: download.id,
        action: 'USER_REJECTED',
        reason: reason || 'User blocked download',
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || '',
      },
    })

    res.json({
      rejected: true,
      blocked: true,
      message: `Download blocked: ${download.filename}`,
    })
  } catch (error) {
    console.error('[Zero Trust] Reject failed:', error)
    res.status(500).json({ error: 'Rejection failed' })
  }
})

router.post('/:downloadId/quarantine', async (req: Request, res: Response) => {
  try {
    const { downloadId } = req.params
    const { reason } = req.body

    const existing = await prisma.downloadRecord.findUnique({
      where: { id: downloadId },
    })

    if (!existing) {
      return res.status(404).json({ error: 'DOWNLOAD_NOT_FOUND', message: 'Download not found' })
    }

    const download = await prisma.downloadRecord.update({
      where: { id: downloadId },
      data: {
        status: 'QUARANTINED',
        approvalStatus: 'USER_APPROVED',
        userAction: 'QUARANTINE',
        userActionReason: reason || 'User chose quarantine',
        userActionTime: new Date(),
      },
    })

    console.log(`[Zero Trust] User QUARANTINED: ${download.filename}`)

    await prisma.downloadAudit.create({
      data: {
        downloadId: download.id,
        action: 'USER_QUARANTINED',
        reason: reason || 'User quarantined file for analysis',
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || '',
      },
    })

    res.json({
      quarantined: true,
      blocked: true,
      message: `File quarantined: ${download.filename}`,
    })
  } catch (error) {
    console.error('[Zero Trust] Quarantine failed:', error)
    res.status(500).json({ error: 'Quarantine failed' })
  }
})

router.post('/:downloadId/complete', async (req: Request, res: Response) => {
  try {
    const { downloadId } = req.params
    const { reason } = req.body

    const existing = await prisma.downloadRecord.findUnique({
      where: { id: downloadId },
    })

    if (!existing) {
      return res.status(404).json({ error: 'DOWNLOAD_NOT_FOUND', message: 'Download not found' })
    }

    const shouldUpdate =
      existing.approvalStatus === 'WAITING_USER' &&
      (existing.status === 'PENDING_REVIEW' || existing.status === 'BLOCKED')

    const download = shouldUpdate
      ? await prisma.downloadRecord.update({
          where: { id: downloadId },
          data: {
            status: 'DOWNLOADED_UNREVIEWED',
            userAction: 'DOWNLOADED_UNREVIEWED',
            userActionReason: reason || 'Download completed before explicit user decision',
            userActionTime: new Date(),
          },
        })
      : existing

    await prisma.downloadAudit.create({
      data: {
        downloadId: download.id,
        action: 'DOWNLOAD_COMPLETED',
        reason: reason || 'Download completed before explicit user decision',
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || '',
      },
    })

    res.json({
      completed: true,
      status: download.status,
      approvalStatus: download.approvalStatus,
    })
  } catch (error) {
    console.error('[Zero Trust] Complete failed:', error)
    res.status(500).json({ error: 'Completion sync failed' })
  }
})

router.get('/session/:tabId', async (req: Request, res: Response) => {
  try {
    const { tabId } = req.params

    const downloads = await prisma.downloadRecord.findMany({
      where: { tabId: parseInt(tabId, 10) },
      orderBy: { createdAt: 'desc' },
    })

    const stats = {
      totalAttempted: downloads.length,
      blocked: downloads.filter((d) => d.status === 'BLOCKED').length,
      pendingReview: downloads.filter((d) => d.status === 'PENDING_REVIEW').length,
      pendingApproval: downloads.filter((d) => d.approvalStatus === 'WAITING_USER').length,
      approved: downloads.filter((d) => d.status === 'APPROVED').length,
      rejected: downloads.filter((d) => d.status === 'REJECTED').length,
      quarantined: downloads.filter((d) => d.status === 'QUARANTINED').length,
      downloadedUnreviewed: downloads.filter((d) => d.status === 'DOWNLOADED_UNREVIEWED').length,
    }

    res.json({
      tabId,
      downloads: downloads.map((d) => ({
        id: d.id,
        filename: d.filename,
        size: d.fileSize,
        status: d.status,
        approvalStatus: d.approvalStatus,
        sourceUrl: d.sourceUrl,
        timestamp: d.createdAt,
      })),
      stats,
    })
  } catch (error) {
    console.error('[Zero Trust] Get session failed:', error)
    res.status(500).json({ error: 'Could not get session downloads' })
  }
})

router.get('/', async (_req: Request, res: Response) => {
  try {
    const downloads = await prisma.downloadRecord.findMany({
      orderBy: { createdAt: 'desc' },
      take: 100,
      include: {
        auditTrail: true,
      },
    })

    res.json({
      totalDownloads: downloads.length,
      downloads: downloads.map((d) => ({
        id: d.id,
        filename: d.filename,
        status: d.status,
        approvalStatus: d.approvalStatus,
        userAction: d.userAction,
        sourceHostname: d.sourceHostname,
        timestamp: d.createdAt,
      })),
    })
  } catch (error) {
    console.error('[Zero Trust] Get all downloads failed:', error)
    res.status(500).json({ error: 'Could not get downloads' })
  }
})

async function analyzeDownloadWithGemini(
  downloadId: string,
  filename: string,
  extension: string,
  mimeType: string
) {
  try {
    const analysis = await analyzeDownload({ filename, extension, mimeType })

    const download = await prisma.downloadRecord.update({
      where: { id: downloadId },
      data: {
        aiAnalysis: JSON.stringify(analysis),
        malwareSuspected: analysis.verdict === 'MALICIOUS',
        riskScore: analysis.score,
      },
    })

    console.log(`[Zero Trust] AI analysis complete: ${downloadId} - ${analysis.verdict}`)

    // Persist medium+ risk AI verdicts into central detection_events for auditability
    const numericScore = typeof analysis.score === 'number'
      ? Math.max(0, Math.min(100, analysis.score))
      : 0

    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    if (numericScore >= 80) riskLevel = 'CRITICAL'
    else if (numericScore >= 60) riskLevel = 'HIGH'
    else if (numericScore >= 30) riskLevel = 'MEDIUM'

    if (riskLevel !== 'LOW') {
      const domain = download.sourceHostname || (() => {
        try { return new URL(download.sourceUrl).hostname } catch { return download.sourceUrl }
      })()

      // Ensure domain_scores row exists for FK requirements
      await prisma.domainScore.upsert({
        where: { domain },
        update: {},
        create: { domain },
      }).catch(() => {})

      await prisma.detectionEvent.create({
        data: {
          eventType: 'file_scan',
          domain,
          url: download.sourceUrl,
          riskScore: numericScore,
          riskLevel,
          verdict: analysis.verdict,
          signals: {
            filename,
            extension,
            mimeType,
            aiScore: numericScore,
            indicators: analysis.indicators ?? [],
          } as any,
          aiExplanation: analysis.explanation ?? undefined,
        },
      }).catch(() => {})
    }
  } catch (error) {
    console.error('[Zero Trust] AI analysis failed:', error)
  }
}

async function checkFileDatabase(download: any): Promise<{
  found: boolean
  knownMalicious: boolean
  previousIncidents: number
  relatedThreats: string[]
}> {
  try {
    const match = await prisma.maliciousFile.findFirst({
      where: {
        OR: [
          { filename: download.filename },
          { extension: download.extension },
        ],
      },
    })

    if (match) {
      return {
        found: true,
        knownMalicious: match.isMalicious,
        previousIncidents: match.incidents,
        relatedThreats: match.threats ? JSON.parse(match.threats) : [],
      }
    }

    return {
      found: false,
      knownMalicious: false,
      previousIncidents: 0,
      relatedThreats: [],
    }
  } catch (error) {
    console.error('[Zero Trust] Database check failed:', error)
    return {
      found: false,
      knownMalicious: false,
      previousIncidents: 0,
      relatedThreats: [],
    }
  }
}

export default router
