export interface DomInspectionResult {
  domRisk: number;
  warnings: string[];
  signalsUsed: string[];
  hasMaliciousScriptInjection: boolean;
  hasOverlayTrap: boolean;
}

export interface ClickInteractionResult {
  interactionRisk: number;
  warnings: string[];
  signalsUsed: string[];
  hasClickInterception: boolean;
}

const getSignal = (signals: Record<string, number>, keys: string[]): number =>
  keys.reduce((max, key) => Math.max(max, Number(signals[key] ?? 0)), 0);

export function computeDomRisk(signals?: Record<string, number>): DomInspectionResult {
  const normalized = signals ?? {};
  let domRisk = 0;
  const warnings: string[] = [];
  const signalsUsed: string[] = [];

  const hiddenIframes = getSignal(normalized, ['hiddenIframes', 'hiddenIframeChains']);
  if (hiddenIframes > 5) {
    domRisk += Math.min(24, (hiddenIframes - 5) * 4);
    warnings.push('High volume of hidden iframes detected');
    signalsUsed.push('hidden_iframe_chain');
  }

  const injectedScripts = getSignal(normalized, ['scriptInjection', 'maliciousScriptInjection', 'injectedScripts']);
  if (injectedScripts > 0) {
    domRisk += 55;
    warnings.push('Injected or malicious script behavior detected');
    signalsUsed.push('script_injection');
  }

  const obfuscatedScripts = getSignal(normalized, ['obfuscatedScripts', 'scriptObfuscation']);
  if (obfuscatedScripts > 0) {
    domRisk += Math.min(20, obfuscatedScripts * 10);
    warnings.push('Obfuscated script activity detected');
    signalsUsed.push('obfuscated_scripts');
  }

  const eventHijacking = getSignal(normalized, ['eventHijacking', 'onclickOverrides']);
  if (eventHijacking > 0) {
    domRisk += Math.min(18, eventHijacking * 9);
    warnings.push('Page event handlers are intercepting user actions');
    signalsUsed.push('event_hijacking');
  }

  const overlayTrap = getSignal(normalized, ['fakeUiOverlay', 'overlayTrap', 'fakeLoginOverlay', 'invisibleOverlay']);
  if (overlayTrap > 0) {
    domRisk += 45;
    warnings.push('Deceptive overlay or clickjacking layer detected');
    signalsUsed.push('overlay_trap');
  }

  return {
    domRisk: Math.min(100, domRisk),
    warnings: Array.from(new Set(warnings)),
    signalsUsed: Array.from(new Set(signalsUsed)),
    hasMaliciousScriptInjection: injectedScripts > 0,
    hasOverlayTrap: overlayTrap > 0
  };
}

export function computeInteractionRisk(signals?: Record<string, number>): ClickInteractionResult {
  const normalized = signals ?? {};
  let interactionRisk = 0;
  const warnings: string[] = [];
  const signalsUsed: string[] = [];

  const deceptiveClicks = getSignal(normalized, ['deceptiveClickFlows', 'fakePlayButtons', 'fakeDownloadButtons']);
  if (deceptiveClicks > 0) {
    interactionRisk += 30;
    warnings.push('Deceptive click flow detected');
    signalsUsed.push('deceptive_click_flow');
  }

  const forcedRedirects = getSignal(normalized, ['forcedRedirects', 'postClickRedirectChains']);
  if (forcedRedirects > 0) {
    interactionRisk += 25;
    warnings.push('Clicks lead through forced redirect chains');
    signalsUsed.push('forced_redirects');
  }

  const hiddenClickTraps = getSignal(normalized, ['hiddenClickTraps', 'clickInterception', 'mismatchedLinkDestinations']);
  if (hiddenClickTraps > 0) {
    interactionRisk += 40;
    warnings.push('Hidden click interception or mismatched link targets detected');
    signalsUsed.push('click_interception');
  }

  const autoDownloadOnClick = getSignal(normalized, ['autoDownloadOnClick', 'downloadWithoutIntent']);
  if (autoDownloadOnClick > 0) {
    interactionRisk += 30;
    warnings.push('Clicks trigger downloads without clear user intent');
    signalsUsed.push('unexpected_download_click');
  }

  return {
    interactionRisk: Math.min(100, interactionRisk),
    warnings: Array.from(new Set(warnings)),
    signalsUsed: Array.from(new Set(signalsUsed)),
    hasClickInterception: hiddenClickTraps > 0
  };
}
