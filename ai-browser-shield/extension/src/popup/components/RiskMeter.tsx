import type { RiskLevel } from '../../types'

const riskMeta: Record<RiskLevel, { label: string; stroke: string; note: string }> = {
  LOW: { label: 'SAFE', stroke: '#10b981', note: '0-25: low risk' },
  MEDIUM: { label: 'CAUTION', stroke: '#f59e0b', note: '26-50: slow down and verify' },
  HIGH: { label: 'WARNING', stroke: '#f97316', note: '51-75: likely threat' },
  CRITICAL: { label: 'BLOCK', stroke: '#ef4444', note: '76-100: avoid this page' },
}

interface RiskMeterProps {
  score: number
  riskLevel: RiskLevel
}

export function RiskMeter({ score, riskLevel }: RiskMeterProps) {
  const normalized = Math.max(0, Math.min(100, Math.round(score)))
  const radius = 58
  const circumference = Math.PI * radius
  const dashOffset = circumference - (normalized / 100) * circumference
  const meta = riskMeta[riskLevel]

  return (
    <section className="rounded-3xl border border-slate-700 bg-slate-950/80 p-5 text-center text-slate-100">
      <div className="mx-auto mb-4 w-fit rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs uppercase tracking-[0.2em] text-slate-400">
        Page Risk
      </div>
      <div className="relative mx-auto h-[140px] w-[180px]">
        <svg viewBox="0 0 180 120" className="h-full w-full">
          <path
            d="M30 100 A60 60 0 0 1 150 100"
            fill="none"
            stroke="rgba(148,163,184,0.22)"
            strokeWidth="12"
            strokeLinecap="round"
          />
          <path
            d="M30 100 A60 60 0 0 1 150 100"
            fill="none"
            stroke={meta.stroke}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{ transition: 'stroke-dashoffset 300ms ease-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pt-8">
          <div className="text-4xl font-semibold text-white">{normalized}</div>
          <div className="mt-1 text-sm font-medium tracking-[0.16em]" style={{ color: meta.stroke }}>
            {meta.label}
          </div>
          <div className="mt-2 text-xs text-slate-400">{meta.note}</div>
        </div>
      </div>
    </section>
  )
}
