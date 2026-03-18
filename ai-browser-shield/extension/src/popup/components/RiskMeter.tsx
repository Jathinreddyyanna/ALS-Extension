import { motion, useReducedMotion } from 'framer-motion';
import { useMemo } from 'react';
import type { RiskLevel } from '@/types/index';
import { riskLabels } from '@/lib/riskLabels';

const describeRisk = (riskLevel: RiskLevel) => riskLabels[riskLevel].label;

export const RiskMeter = ({ score, riskLevel, animated = true }: { score: number; riskLevel: RiskLevel; animated?: boolean }) => {
  const reduceMotion = useReducedMotion();
  const normalized = Math.max(0, Math.min(100, score));
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (normalized / 100) * circumference * 0.75;
  const stroke = riskLevel === 'LOW' ? 'var(--safe)' : riskLevel === 'MEDIUM' ? 'var(--caution)' : riskLevel === 'HIGH' ? 'var(--danger)' : 'var(--critical)';
  const scoreText = useMemo(() => normalized, [normalized]);

  return (
    <div className="relative flex flex-col items-center gap-2" title="This score combines URL analysis, AI assessment, and community reports">
      <svg width="170" height="130" viewBox="0 0 170 130" className="overflow-visible" aria-hidden="true">
        <path d="M25 105 A60 60 0 1 1 145 105" fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="12" strokeLinecap="round" />
        <motion.path
          d="M25 105 A60 60 0 1 1 145 105"
          fill="none"
          stroke={stroke}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${circumference * 0.75} ${circumference}`}
          initial={reduceMotion || !animated ? false : { strokeDashoffset: circumference * 0.75 }}
          animate={{ strokeDashoffset: dashOffset }}
          transition={{ duration: 0.7, ease: 'easeOut' }}
        />
      </svg>
      <div className="-mt-20 flex flex-col items-center">
        <span className="caption">Risk score</span>
        <motion.span
          className="font-mono text-score"
          initial={reduceMotion || !animated ? false : { opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
        >
          {scoreText}
        </motion.span>
        <span className="subheading">{describeRisk(riskLevel)}</span>
      </div>
    </div>
  );
};
