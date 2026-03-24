type CounterMap = Map<string, number>;

const counters: CounterMap = new Map();
const latencies: Map<string, number[]> = new Map();

export function incrementMetric(name: string, labels: Record<string, string> = {}): void {
  const key = `${name}${JSON.stringify(labels)}`;
  counters.set(key, (counters.get(key) ?? 0) + 1);
}

export function observeLatency(name: string, valueMs: number): void {
  const current = latencies.get(name) ?? [];
  current.push(valueMs);
  if (current.length > 500) {
    current.shift();
  }
  latencies.set(name, current);
}

function percentile(values: number[], target: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.floor(target * sorted.length)));
  return sorted[index] ?? 0;
}

export function renderPrometheusMetrics(): string {
  const lines: string[] = [
    '# HELP abs_requests_total Total counted application requests',
    '# TYPE abs_requests_total counter'
  ];

  for (const [key, value] of counters.entries()) {
    lines.push(`abs_requests_total{key="${key.replace(/"/g, '\\"')}"} ${value}`);
  }

  lines.push('# HELP abs_scan_latency_p95_ms Rolling scan latency p95 in ms');
  lines.push('# TYPE abs_scan_latency_p95_ms gauge');
  lines.push(`abs_scan_latency_p95_ms ${percentile(latencies.get('scan') ?? [], 0.95)}`);

  return `${lines.join('\n')}\n`;
}
