import type { LucideIcon } from 'lucide-react'

type Tone = 'safe' | 'caution' | 'danger'

const toneStyles: Record<Tone, string> = {
  safe: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100',
  caution: 'border-amber-500/30 bg-amber-500/10 text-amber-100',
  danger: 'border-rose-500/30 bg-rose-500/10 text-rose-100',
}

interface SignalCardProps {
  title: string
  value: string | number
  detail: string
  tone: Tone
  icon: LucideIcon
  loading?: boolean
}

export function SignalCard({
  title,
  value,
  detail,
  tone,
  icon: Icon,
  loading = false,
}: SignalCardProps) {
  return (
    <div className={`rounded-2xl border p-4 ${toneStyles[tone]}`}>
      <div className="mb-3 flex items-center justify-between">
        <div className="rounded-xl bg-white/10 p-2">
          <Icon className="h-4 w-4" />
        </div>
        <div className="text-right">
          <div className="text-xs uppercase tracking-[0.18em] text-white/60">{title}</div>
          <div className="text-xl font-semibold text-white">
            {loading ? '...' : value}
          </div>
        </div>
      </div>
      <p className="text-sm leading-5 text-white/75">
        {loading ? 'Collecting the latest signal for this page.' : detail}
      </p>
    </div>
  )
}
