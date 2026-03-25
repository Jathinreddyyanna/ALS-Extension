import { Bot, ListChecks } from 'lucide-react'

interface ExplanationCardProps {
  explanation: string
  confidence?: number
  keyIndicators?: string[]
  sourceLabel?: string
}

export function ExplanationCard({
  explanation,
  confidence,
  keyIndicators = [],
  sourceLabel = 'Threat explanation',
}: ExplanationCardProps) {
  const percent = typeof confidence === 'number'
    ? Math.max(1, Math.min(100, Math.round(confidence * 100)))
    : null

  return (
    <section className="rounded-2xl border border-slate-700 bg-slate-900/80 p-4 text-slate-100">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Bot className="h-4 w-4 text-cyan-300" />
          {sourceLabel}
        </div>
        {percent !== null && (
          <div className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">
            Confidence {percent}%
          </div>
        )}
      </div>
      <p className="text-sm leading-6 text-slate-200">
        {explanation || 'No explanation is available yet. Reload the page to refresh the scan.'}
      </p>
      <div className="mt-4">
        <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-400">
          <ListChecks className="h-3.5 w-3.5" />
          Key Indicators
        </div>
        {keyIndicators.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {keyIndicators.slice(0, 6).map((indicator) => (
              <span
                key={indicator}
                className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1 text-xs text-slate-200"
              >
                {indicator}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-400">No major indicators were surfaced for this scan.</p>
        )}
      </div>
    </section>
  )
}
