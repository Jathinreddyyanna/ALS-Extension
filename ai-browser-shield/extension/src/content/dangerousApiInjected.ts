/**
 * Dangerous API injected script - runs in MAIN world.
 * This file must remain standalone and import-free.
 */
(() => {
  const EVENT_TYPE = 'ABS_PAGE_DANGEROUS_API';

  const looksLikeRedirect = (value: unknown) =>
    /(window\.location|location\.(assign|replace|href)|top\.location|document\.location)\s*(=|\()/.test(String(value ?? ''));

  const emit = (kind: string, value: unknown) => {
    try {
      window.postMessage({
        type: EVENT_TYPE,
        payload: {
          kind,
          value: String(value ?? '')
        }
      }, '*');
    } catch {
      // Never break page execution.
    }
  };

  try {
    const originalOpen = window.open.bind(window);
    window.open = function (...args: Parameters<typeof window.open>) {
      emit('window_open', args[0]);
      return originalOpen(...args);
    };
  } catch {
    // Ignore window.open hook failures.
  }

  try {
    const originalEval = window.eval.bind(window);
    window.eval = function (code: string) {
      if (looksLikeRedirect(code)) {
        emit('eval_redirect', code);
      }
      return originalEval(code);
    };
  } catch {
    // Ignore eval hook failures.
  }

  try {
    const OriginalFunction = window.Function;
    const WrappedFunction = function (this: unknown, ...args: string[]) {
      const body = args.at(-1);
      if (looksLikeRedirect(body)) {
        emit('function_redirect', body);
      }
      return OriginalFunction.apply(this, args);
    };
    WrappedFunction.prototype = OriginalFunction.prototype;
    Object.defineProperty(window, 'Function', {
      configurable: true,
      writable: true,
      value: WrappedFunction
    });
  } catch {
    // Ignore Function hook failures.
  }
})();
