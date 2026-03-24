import { logger } from '../utils/logger';

interface CircuitState {
  failures: number;
  openedAt: number | null;
}

interface ResilientTaskOptions {
  name: string;
  retries?: number;
  baseDelayMs?: number;
  timeoutMs?: number;
  circuitThreshold?: number;
  circuitCooldownMs?: number;
  onError?: (error: unknown, attempt: number) => void;
}

const circuits = new Map<string, CircuitState>();

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function getCircuitState(name: string): CircuitState {
  return circuits.get(name) ?? { failures: 0, openedAt: null };
}

function isCircuitOpen(name: string, cooldownMs: number): boolean {
  const state = getCircuitState(name);
  if (!state.openedAt) {
    return false;
  }

  if (Date.now() - state.openedAt > cooldownMs) {
    circuits.set(name, { failures: 0, openedAt: null });
    return false;
  }

  return true;
}

function recordFailure(name: string, threshold: number): void {
  const state = getCircuitState(name);
  const failures = state.failures + 1;
  circuits.set(name, {
    failures,
    openedAt: failures >= threshold ? Date.now() : state.openedAt
  });
}

function recordSuccess(name: string): void {
  circuits.set(name, { failures: 0, openedAt: null });
}

async function withTimeout<T>(task: () => Promise<T>, timeoutMs?: number): Promise<T> {
  if (!timeoutMs || timeoutMs <= 0) {
    return task();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await task();
  } finally {
    clearTimeout(timeout);
  }
}

export async function runResilientTask<T>(
  task: () => Promise<T>,
  options: ResilientTaskOptions
): Promise<T> {
  const retries = options.retries ?? 1;
  const baseDelayMs = options.baseDelayMs ?? 250;
  const circuitThreshold = options.circuitThreshold ?? 3;
  const circuitCooldownMs = options.circuitCooldownMs ?? 60_000;

  if (isCircuitOpen(options.name, circuitCooldownMs)) {
    throw new Error(`${options.name}_circuit_open`);
  }

  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const result = await withTimeout(task, options.timeoutMs);
      recordSuccess(options.name);
      return result;
    } catch (error) {
      lastError = error;
      options.onError?.(error, attempt);
      if (attempt < retries) {
        await sleep(baseDelayMs * (2 ** attempt));
      }
    }
  }

  recordFailure(options.name, circuitThreshold);
  logger.warn({ task: options.name, err: lastError }, 'resilient task exhausted retries');
  throw lastError;
}
