import { useEffect } from 'react'
import { Activity, AlertTriangle, Globe, Mail, RefreshCcw, ShieldCheck, Siren } from 'lucide-react'
import { ExplanationCard } from './components/ExplanationCard'
import { RiskMeter } from './components/RiskMeter'
import { SignalCard } from './components/SignalCard'
import { useStore } from './store'

function formatActivity(detail: string): string {
  return detail
    .replace(/_/g, ' ')
    .replace(/\burl threat\b/i, 'page threat')
    .replace(/\bpopup abuse\b/i, 'popup abuse')
    .replace(/\bredirect chain\b/i, 'redirect chain')
}

export default function App() {
  const {
    initialize,
    rescan,
    resetEmail,
    isLoading,
    error,
    currentDomain,
    scanResult,
    emailState,
  } = useStore()

  useEffect(() => {
    void initialize()
  }, [initialize])

  const activity = scanResult?.activityLog?.slice(0, 6) ?? []
  const confidence = scanResult?.confidence ?? 0.45
  const warnings = scanResult?.warnings ?? []
  const positives = scanResult?.positives ?? []
  const emailTopSignals = emailState.detectedPatterns.slice(0, 4)

  return (
    <div className="min-h-[560px] w-[390px] bg-slate-950 p-4 text-slate-100">
      <header className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="text-lg font-semibold">AI Browser Shield</div>
          <div className="mt-1 text-sm text-slate-400">
            {currentDomain || 'Waiting for an active page'}
          </div>
        </div>
        <button
          type="button"
          onClick={() => void rescan()}
          className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"
        >
          <RefreshCcw className="h-4 w-4" />
        </button>
      </header>

      {error && (
        <div className="mb-4 rounded-2xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">
          {error}
        </div>
      )}

      {scanResult ? (
        <div className="space-y-4">
          <RiskMeter score={scanResult.riskScore} riskLevel={scanResult.riskLevel} />

          <div className="grid grid-cols-2 gap-3">
            <SignalCard
              title="Confidence"
              value={`${Math.max(1, Math.round(confidence * 100))}%`}
              detail={scanResult.aiDegraded ? 'Using built-in reasoning for explanation.' : 'Gemini explanation is active for this scan.'}
              tone={scanResult.riskScore >= 76 ? 'danger' : scanResult.riskScore >= 26 ? 'caution' : 'safe'}
              icon={ShieldCheck}
              loading={isLoading}
            />
            <SignalCard
              title="Signals"
              value={scanResult.keyIndicators.length}
              detail={scanResult.keyIndicators[0] || 'No major phishing indicators were surfaced.'}
              tone={scanResult.keyIndicators.length >= 3 ? 'danger' : scanResult.keyIndicators.length > 0 ? 'caution' : 'safe'}
              icon={Siren}
              loading={isLoading}
            />
            <SignalCard
              title="Warnings"
              value={warnings.length}
              detail={warnings[0] || 'No notable runtime warnings were recorded.'}
              tone={warnings.length > 1 ? 'danger' : warnings.length === 1 ? 'caution' : 'safe'}
              icon={AlertTriangle}
              loading={isLoading}
            />
            <SignalCard
              title="Trust"
              value={positives.length}
              detail={positives[0] || 'No strong trust signals were recorded.'}
              tone={positives.length > 0 && scanResult.riskScore <= 25 ? 'safe' : scanResult.riskScore >= 51 ? 'danger' : 'caution'}
              icon={Globe}
              loading={isLoading}
            />
          </div>

          <ExplanationCard
            explanation={scanResult.explanation || scanResult.aiExplanation || 'No explanation is available for this page yet.'}
            confidence={confidence}
            keyIndicators={scanResult.keyIndicators}
            sourceLabel={scanResult.aiDegraded ? 'Built-in threat explanation' : 'AI threat explanation'}
          />

          <section className="rounded-2xl border border-slate-700 bg-slate-900/80 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold">
                <Mail className="h-4 w-4 text-cyan-300" />
                Email Risk
              </div>
              <button
                type="button"
                onClick={() => void resetEmail()}
                className="rounded-lg border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
              >
                Clear
              </button>
            </div>

            {emailState.status === 'waiting' && !emailState.emailText ? (
              <p className="text-sm text-slate-400">
                Open any webmail message and the extension will extract and analyze it automatically.
              </p>
            ) : (
              <div className="space-y-3">
                <div className="flex items-end justify-between gap-3">
                  <div>
                    <div className="text-3xl font-semibold text-white">{emailState.riskScore}</div>
                    <div className="text-xs uppercase tracking-[0.18em] text-slate-400">
                      {emailState.riskLabel}
                    </div>
                  </div>
                  <div className="text-right text-sm text-slate-300">
                    <div>Confidence {Math.max(1, Math.round(emailState.confidence))}%</div>
                    <div className="text-xs text-slate-500">{emailState.status.replace(/_/g, ' ')}</div>
                  </div>
                </div>

                <p className="text-sm leading-6 text-slate-200">
                  {emailState.explanation || 'Email extraction is active, but a message body has not been analyzed yet.'}
                </p>

                <div className="grid gap-2 text-sm text-slate-300">
                  <div><span className="text-slate-500">Sender:</span> {emailState.senderEmail || 'Unknown sender'}</div>
                  <div><span className="text-slate-500">Subject:</span> {emailState.subject || 'No subject detected'}</div>
                  <div><span className="text-slate-500">Attachments:</span> {emailState.hasAttachments ? emailState.attachmentNames.join(', ') || 'Detected' : 'None detected'}</div>
                </div>

                {emailTopSignals.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {emailTopSignals.map((signal) => (
                      <span key={signal} className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1 text-xs text-slate-200">
                        {signal}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </section>

          <section className="rounded-2xl border border-slate-700 bg-slate-900/80 p-4">
            <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
              <Activity className="h-4 w-4 text-cyan-300" />
              Activity Feed
            </div>
            {activity.length > 0 ? (
              <div className="space-y-2">
                {activity.map((item) => (
                  <div key={`${item.type}-${item.timestamp}-${item.detail}`} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                    <div className="text-sm text-slate-200">{formatActivity(item.detail)}</div>
                    <div className="mt-1 text-xs uppercase tracking-[0.16em] text-slate-500">
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-400">No recent page activity has been recorded yet.</p>
            )}
          </section>
        </div>
      ) : (
        <div className="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 text-sm text-slate-400">
          {isLoading ? 'Loading the latest page scan...' : 'Open a web page to start protection analysis.'}
        </div>
      )}
    </div>
  )
}
