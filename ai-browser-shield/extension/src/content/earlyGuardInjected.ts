/**
 * Early guard injected script - runs in MAIN world (page context).
 * This file must NOT import anything - it runs as a standalone script.
 * Intercepts location-based redirects before site scripts can perform them.
 */
(() => {
  const EVENT_TYPE = 'ABS_EARLY_REDIRECT_ATTEMPT';

  const report = (method: 'assign' | 'replace' | 'href', url: unknown) => {
    try {
      window.postMessage({
        type: EVENT_TYPE,
        payload: {
          url: String(url ?? ''),
          timestamp: Date.now(),
          method
        }
      }, '*');
    } catch {
      // Silent fail - never break page execution
    }
  };

  // Hook window.location.assign
  try {
    const originalAssign = window.location.assign.bind(window.location);
    window.location.assign = function(url: string | URL) {
      report('assign', url);
      return originalAssign(url);
    };
  } catch {
    // Some pages may block this
  }

  // Hook window.location.replace
  try {
    const originalReplace = window.location.replace.bind(window.location);
    window.location.replace = function(url: string | URL) {
      report('replace', url);
      return originalReplace(url);
    };
  } catch {
    // Some pages may block this
  }

  // Hook window.location.href setter
  try {
    const descriptor = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (descriptor?.set && descriptor.get) {
      Object.defineProperty(window.location, 'href', {
        configurable: true,
        enumerable: true,
        get() {
          return descriptor.get!.call(window.location);
        },
        set(value: string) {
          report('href', value);
          return descriptor.set!.call(window.location, value);
        }
      });
    }
  } catch {
    // Some pages may block property redefinition
  }
})();
