-- CreateEnum
CREATE TYPE "event_type" AS ENUM ('url_threat', 'redirect_chain', 'popup_abuse', 'download_intercept', 'file_scan', 'ad_block');

-- CreateEnum
CREATE TYPE "file_verdict" AS ENUM ('SAFE', 'SUSPICIOUS', 'MALICIOUS');

-- CreateEnum
CREATE TYPE "risk_level" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "threat_category" AS ENUM ('phishing', 'scam', 'malware', 'redirect', 'popup_abuse', 'other');

-- CreateTable
CREATE TABLE "threat_reports" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "url" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "category" "threat_category" NOT NULL,
    "description" VARCHAR(500),
    "signals" JSONB,
    "ip_hash" TEXT NOT NULL,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMPTZ(6),
    "created_hour" TIMESTAMPTZ(6),

    CONSTRAINT "threat_reports_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detection_events" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "event_type" "event_type" NOT NULL,
    "domain" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "risk_score" INTEGER NOT NULL,
    "risk_level" "risk_level" NOT NULL,
    "signals" JSONB,
    "ai_explanation" TEXT,
    "verdict" "file_verdict",
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "file_scan_id" UUID,

    CONSTRAINT "detection_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "domain_scores" (
    "domain" TEXT NOT NULL,
    "risk_score" INTEGER NOT NULL DEFAULT 0,
    "report_count" INTEGER NOT NULL DEFAULT 0,
    "categories" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "category_counts" JSONB NOT NULL DEFAULT '{}',
    "is_confirmed" BOOLEAN NOT NULL DEFAULT false,
    "first_seen" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_report_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_updated" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "domain_scores_pkey" PRIMARY KEY ("domain")
);

-- CreateTable
CREATE TABLE "file_scans" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "filename" TEXT NOT NULL,
    "extension" TEXT NOT NULL,
    "mime_type" TEXT NOT NULL,
    "size_bytes" BIGINT NOT NULL,
    "source_url" TEXT NOT NULL,
    "chrome_download_id" INTEGER,
    "verdict" "file_verdict" NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "ai_explanation" TEXT NOT NULL,
    "indicators" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "recommended_action" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "file_scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DownloadRecord" (
    "id" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "extension" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "fileSize" INTEGER NOT NULL,
    "sourceUrl" TEXT NOT NULL,
    "sourceHostname" TEXT NOT NULL,
    "tabId" INTEGER NOT NULL,
    "status" TEXT NOT NULL,
    "approvalStatus" TEXT NOT NULL,
    "userAction" TEXT,
    "userActionReason" TEXT,
    "userActionTime" TIMESTAMP(3),
    "aiAnalysis" TEXT,
    "riskScore" INTEGER,
    "malwareSuspected" BOOLEAN NOT NULL DEFAULT false,
    "knownMalicious" BOOLEAN NOT NULL DEFAULT false,
    "previousIncidents" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DownloadRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DownloadAudit" (
    "id" TEXT NOT NULL,
    "downloadId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "reason" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DownloadAudit_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MaliciousFile" (
    "id" TEXT NOT NULL,
    "filename" TEXT,
    "extension" TEXT,
    "fileHash" TEXT,
    "isMalicious" BOOLEAN NOT NULL,
    "incidents" INTEGER NOT NULL DEFAULT 0,
    "threats" TEXT,
    "lastSeen" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MaliciousFile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app_stats" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "total_reports" BIGINT NOT NULL DEFAULT 0,
    "total_detection_events" BIGINT NOT NULL DEFAULT 0,
    "total_file_scans" BIGINT NOT NULL DEFAULT 0,
    "malicious_files" BIGINT NOT NULL DEFAULT 0,
    "high_risk_domains" INTEGER NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "app_stats_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rate_limit_log" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "ip_hash" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "rate_limit_log_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "idx_threat_reports_category" ON "threat_reports"("category");

-- CreateIndex
CREATE INDEX "idx_threat_reports_created_at" ON "threat_reports"("created_at" DESC);

-- CreateIndex
CREATE INDEX "idx_threat_reports_domain" ON "threat_reports"("domain");

-- CreateIndex
CREATE INDEX "idx_detection_events_created_at" ON "detection_events"("created_at" DESC);

-- CreateIndex
CREATE INDEX "idx_detection_events_domain" ON "detection_events"("domain");

-- CreateIndex
CREATE INDEX "idx_detection_events_event_type" ON "detection_events"("event_type");

-- CreateIndex
CREATE INDEX "idx_detection_events_risk_level" ON "detection_events"("risk_level");

-- CreateIndex
CREATE INDEX "idx_domain_scores_last_report" ON "domain_scores"("last_report_at" DESC);

-- CreateIndex
CREATE INDEX "idx_domain_scores_risk" ON "domain_scores"("risk_score" DESC);

-- CreateIndex
CREATE INDEX "idx_domain_scores_trgm" ON "domain_scores"("domain");

-- CreateIndex
CREATE INDEX "idx_file_scans_created_at" ON "file_scans"("created_at" DESC);

-- CreateIndex
CREATE INDEX "idx_file_scans_extension" ON "file_scans"("extension");

-- CreateIndex
CREATE INDEX "idx_file_scans_verdict" ON "file_scans"("verdict");

-- CreateIndex
CREATE INDEX "DownloadRecord_tabId_idx" ON "DownloadRecord"("tabId");

-- CreateIndex
CREATE INDEX "DownloadRecord_status_idx" ON "DownloadRecord"("status");

-- CreateIndex
CREATE INDEX "DownloadRecord_approvalStatus_idx" ON "DownloadRecord"("approvalStatus");

-- CreateIndex
CREATE INDEX "DownloadRecord_createdAt_idx" ON "DownloadRecord"("createdAt");

-- CreateIndex
CREATE INDEX "DownloadAudit_downloadId_idx" ON "DownloadAudit"("downloadId");

-- CreateIndex
CREATE INDEX "DownloadAudit_action_idx" ON "DownloadAudit"("action");

-- CreateIndex
CREATE UNIQUE INDEX "MaliciousFile_fileHash_key" ON "MaliciousFile"("fileHash");

-- CreateIndex
CREATE INDEX "MaliciousFile_filename_idx" ON "MaliciousFile"("filename");

-- CreateIndex
CREATE INDEX "MaliciousFile_extension_idx" ON "MaliciousFile"("extension");

-- CreateIndex
CREATE INDEX "MaliciousFile_fileHash_idx" ON "MaliciousFile"("fileHash");

-- CreateIndex
CREATE INDEX "idx_rate_limit_ip_endpoint" ON "rate_limit_log"("ip_hash", "endpoint", "created_at" DESC);

-- AddForeignKey
ALTER TABLE "threat_reports" ADD CONSTRAINT "threat_reports_domain_fkey" FOREIGN KEY ("domain") REFERENCES "domain_scores"("domain") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_events" ADD CONSTRAINT "detection_events_domain_fkey" FOREIGN KEY ("domain") REFERENCES "domain_scores"("domain") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detection_events" ADD CONSTRAINT "fk_detection_events_file_scan" FOREIGN KEY ("file_scan_id") REFERENCES "file_scans"("id") ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "DownloadAudit" ADD CONSTRAINT "DownloadAudit_downloadId_fkey" FOREIGN KEY ("downloadId") REFERENCES "DownloadRecord"("id") ON DELETE CASCADE ON UPDATE CASCADE;
