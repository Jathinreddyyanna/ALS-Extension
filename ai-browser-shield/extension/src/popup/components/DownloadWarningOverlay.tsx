import { AnimatePresence, motion } from 'framer-motion';
import { FileSearch } from 'lucide-react';
import { formatFileSize } from '@/lib/formatters';
import type { FileScanResult, RiskLevel } from '@/types/index';
import { RiskBadge } from './RiskBadge';

const verdictToRisk = (verdict: FileScanResult['verdict']): RiskLevel => verdict === 'SAFE' ? 'LOW' : verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'HIGH';

export const DownloadWarningOverlay = ({
  open,
  result,
  fileName,
  fileSize,
  onClose
}: {
  open: boolean;
  result: FileScanResult | null;
  fileName?: string;
  fileSize?: number;
  onClose: () => void;
}) => (
  <AnimatePresence>
    {open && result && (
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-6 backdrop-blur-sm"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <motion.div
          initial={{ opacity: 0, y: 18, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 12 }}
          className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-[var(--shadow-elevated)]"
        >
          <div className="flex items-center gap-4">
            <div className="rounded-full bg-[var(--surface-alt)] p-3">
              <FileSearch className="h-5 w-5" />
            </div>
            <div>
              <p className="subheading">{fileName ?? 'Downloaded file'}</p>
              <p className="caption">{typeof fileSize === 'number' ? formatFileSize(fileSize) : 'Size unavailable'}</p>
            </div>
          </div>
          <div className="mt-6 space-y-3">
            <RiskBadge riskLevel={verdictToRisk(result.verdict)} />
            <p className="text-body">{result.explanation}</p>
          </div>
          <div className="mt-6 flex flex-col gap-3">
            <button type="button" className="min-h-11 rounded-md bg-danger-600 px-4 py-3 font-semibold text-white">Cancel Download</button>
            <button type="button" className="min-h-11 rounded-md bg-caution-600 px-4 py-3 font-semibold text-white">Scan First</button>
            <button type="button" onClick={onClose} className="min-h-11 rounded-md border border-[var(--border)] px-4 py-3 font-semibold text-[var(--text-primary)]">I Understand the Risk</button>
          </div>
        </motion.div>
      </motion.div>
    )}
  </AnimatePresence>
);
