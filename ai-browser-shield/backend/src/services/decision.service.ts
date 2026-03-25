import type { DomainIntelligence } from './domainIntelligence.service';
import type { HeuristicResult } from './scoring.service';
import type { ReputationResult } from './reputation.service';

export interface DecisionResult {
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendedAction: 'allow' | 'warn' | 'block';
  confidence: number;
  decisionBasis: string;
  signalsUsed: string[];
}

export interface ComponentRiskInput {
  structuralRisk: number;
  reputationRisk: number;
  environmentRisk: number;
  behaviorRisk: number;
  runtimeRisk: number;
  domRisk: number;
  interactionRisk: number;
  signalsUsed: string[];
  hasMaliciousScriptInjection?: boolean;
  hasOverlayTrap?: boolean;
  hasClickInterception?: boolean;
}

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const toRiskLevel = (score: number): DecisionResult['riskLevel'] => (
  score >= 76 ? 'CRITICAL'
    : score >= 51 ? 'HIGH'
      : score >= 26 ? 'MEDIUM'
        : 'LOW'
);

const hasStrongPhishingSignals = (heuristic: HeuristicResult): boolean =>
  (heuristic.signals.brandImpersonation ?? 0) >= 20 ||
  (heuristic.signals.subdomainSpoofing ?? 0) >= 20 ||
  ((heuristic.signals.typosquatScore ?? 0) >= 18 && (heuristic.signals.suspiciousTLD ?? 0) >= 10);

function calculateBaseConfidence(
  intel: DomainIntelligence,
  heuristic: HeuristicResult,
  reputation: ReputationResult
): number {
  const reputationCertainty =
    reputation.reputationStatus === 'known_threat' || reputation.reputationStatus === 'known_safe'
      ? 1
      : reputation.reputationStatus === 'community_flagged'
        ? 0.7
        : 0.35;

  const activeSignals = Object.values(heuristic.signals).filter((value) => value > 0);
  const signalAgreement =
    activeSignals.length >= 4 ? 0.9
      : activeSignals.length >= 2 ? 0.7
        : activeSignals.length === 1 ? 0.5
          : 0.35;

  const trustComponent = intel.isOfficialTLD ? 0.95 : clamp(1 - intel.trustScore / 100, 0.2, 0.85);

  return clamp(
    (reputationCertainty * 0.4) +
    (signalAgreement * 0.35) +
    (trustComponent * 0.25),
    0.25,
    0.98
  );
}

export function applyExplanationConsistency(
  decision: DecisionResult,
  explanationConsistency: number
): DecisionResult {
  return {
    ...decision,
    confidence: clamp((decision.confidence * 0.85) + (explanationConsistency * 0.15), 0.2, 0.99)
  };
}

export function makeDecision(
  intel: DomainIntelligence,
  heuristic: HeuristicResult,
  reputation: ReputationResult,
  componentRisk?: ComponentRiskInput
): DecisionResult {
  const signalsUsed = Array.from(new Set(componentRisk?.signalsUsed ?? heuristic.signalsUsed));

  if (reputation.isConfirmed && reputation.reputationStatus === 'known_threat') {
    return {
      riskScore: Math.max(90, reputation.domainRiskScore),
      riskLevel: 'CRITICAL',
      recommendedAction: 'block',
      confidence: 0.98,
      decisionBasis: 'confirmed_threat_database',
      signalsUsed: ['confirmed_threat_database', ...signalsUsed]
    };
  }

  const extremeOfficialRisk =
    intel.hasSubdomainSpoofing ||
    intel.homoglyph.hasHomoglyphRisk ||
    (heuristic.signals.ipAsHostname ?? 0) > 0;

  if (intel.isOfficialTLD && !extremeOfficialRisk) {
    return {
      riskScore: 0,
      riskLevel: 'LOW',
      recommendedAction: 'allow',
      confidence: 0.97,
      decisionBasis: 'official_tld_verified',
      signalsUsed: ['official_tld_verified']
    };
  }

  if (componentRisk) {
    const homoglyphRisk = heuristic.signals.homoglyphRisk ?? 0;
    const subdomainSpoofingRisk = heuristic.signals.subdomainSpoofing ?? 0;
    const brandImpersonationRisk = heuristic.signals.brandImpersonation ?? 0;

    if (componentRisk.hasMaliciousScriptInjection) {
      const riskScore = Math.max(90, componentRisk.domRisk, componentRisk.runtimeRisk);

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'malicious_script_injection_detected',
        signalsUsed
      };
    }

    if (componentRisk.hasOverlayTrap || componentRisk.hasClickInterception) {
      const riskScore = Math.max(82, componentRisk.domRisk, componentRisk.interactionRisk);

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: componentRisk.hasClickInterception ? 'click_interception_detected' : 'overlay_trap_detected',
        signalsUsed
      };
    }

    if (homoglyphRisk > 0) {
      const riskScore = Math.max(
        90,
        componentRisk.structuralRisk,
        componentRisk.behaviorRisk
      );

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'homoglyph_or_punycode_detected',
        signalsUsed
      };
    }

    if (intel.hasSubdomainSpoofing || subdomainSpoofingRisk >= 20) {
      const riskScore = Math.max(
        78,
        componentRisk.structuralRisk,
        componentRisk.behaviorRisk
      );

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'subdomain_spoofing_detected',
        signalsUsed
      };
    }

    if (intel.impersonatedBrand && (brandImpersonationRisk >= 20 || (heuristic.signals.typosquatScore ?? 0) >= 18)) {
      const riskScore = Math.max(
        (heuristic.signals.suspiciousTLD ?? 0) > 0 ? 82 : 76,
        componentRisk.structuralRisk,
        componentRisk.behaviorRisk
      );

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'brand_impersonation_detected',
        signalsUsed
      };
    }

    if (hasStrongPhishingSignals(heuristic)) {
      const riskScore = Math.max(
        72,
        componentRisk.structuralRisk,
        componentRisk.behaviorRisk
      );

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'strong_phishing_signals',
        signalsUsed
      };
    }

    if (componentRisk.runtimeRisk >= 80) {
      const riskScore = Math.max(76, componentRisk.runtimeRisk, componentRisk.behaviorRisk);

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'block',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'runtime_abuse_detected',
        signalsUsed
      };
    }

    if (componentRisk.runtimeRisk >= 60) {
      const riskScore = Math.max(60, componentRisk.runtimeRisk, componentRisk.behaviorRisk);

      return {
        riskScore,
        riskLevel: toRiskLevel(riskScore),
        recommendedAction: 'warn',
        confidence: calculateBaseConfidence(intel, heuristic, reputation),
        decisionBasis: 'runtime_abuse_detected',
        signalsUsed
      };
    }

    const weightedScore = Math.round(
      (componentRisk.structuralRisk * 0.25) +
      (componentRisk.reputationRisk * 0.15) +
      (componentRisk.environmentRisk * 0.10) +
      (componentRisk.behaviorRisk * 0.20) +
      (componentRisk.runtimeRisk * 0.15) +
      (componentRisk.domRisk * 0.10) +
      (componentRisk.interactionRisk * 0.05)
    );
    const baselineScore = signalsUsed.length === 0
      ? reputation.reputationStatus === 'unknown' && !intel.isOfficialTLD
        ? 36
        : 20
      : 0;
    const unknownSuspiciousFloor =
      reputation.reputationStatus === 'unknown' &&
      !intel.isOfficialTLD &&
      (
        signalsUsed.length > 0 ||
        componentRisk.structuralRisk >= 10 ||
        componentRisk.behaviorRisk >= 10 ||
        componentRisk.environmentRisk >= 10 ||
        componentRisk.runtimeRisk >= 10 ||
        componentRisk.domRisk >= 10 ||
        componentRisk.interactionRisk >= 10
      )
        ? 36
        : 0;
    const unknownDomainFloor =
      reputation.reputationStatus === 'unknown' && !intel.isOfficialTLD
        ? 20
        : 0;
    const runtimeFloor = componentRisk.runtimeRisk > 0 ? 40 : 0;
    const domFloor = componentRisk.domRisk > 0 ? 50 : 0;
    const capped = clamp(Math.max(weightedScore, baselineScore, unknownSuspiciousFloor, unknownDomainFloor, runtimeFloor, domFloor), 0, 100);
    const riskLevel = toRiskLevel(capped);
    const recommendedAction =
      capped >= 76 ? 'block'
        : capped >= 26 ? 'warn'
          : 'allow';

    return {
      riskScore: capped,
      riskLevel,
      recommendedAction,
      confidence: calculateBaseConfidence(intel, heuristic, reputation),
      decisionBasis:
        componentRisk.runtimeRisk >= 40 ? 'runtime_risk_engine'
          : componentRisk.domRisk >= 50 ? 'dom_risk_engine'
            : componentRisk.behaviorRisk >= 55 ? 'behavior_risk_engine'
          : componentRisk.structuralRisk >= 60 ? 'structural_analysis'
            : reputation.reputationStatus === 'community_flagged' ? 'community_intelligence'
              : 'aggregated_risk_model',
      signalsUsed
    };
  }

  const punycodeOrHomoglyph = (heuristic.signals.homoglyphRisk ?? 0) > 0;
  const strongPhishing = hasStrongPhishingSignals(heuristic);
  const repScore = reputation.domainRiskScore;
  const combined = Math.round((heuristic.score * 0.7) + (repScore * 0.3));
  let riskScore = combined;
  let decisionBasis = 'baseline';

  if (punycodeOrHomoglyph) {
    riskScore = Math.max(riskScore, intel.homoglyph.hasPunycode || intel.homoglyph.matchedBrand ? 90 : 80);
    decisionBasis = 'homoglyph_or_punycode_detected';
  } else if (strongPhishing) {
    riskScore = Math.max(riskScore, 72);
    decisionBasis = 'strong_phishing_signals';
  } else if (reputation.reputationStatus === 'community_flagged') {
    riskScore = Math.max(riskScore, repScore >= 60 ? 65 : 45);
    decisionBasis = 'community_intelligence';
  } else if (signalsUsed.length > 0) {
    riskScore = Math.max(riskScore, heuristic.score);
    decisionBasis = 'mixed_heuristic_signals';
  } else if (reputation.reputationStatus === 'unknown') {
    riskScore = Math.max(riskScore, 8);
    decisionBasis = 'unknown_reputation_baseline';
  }

  if (intel.hasSubdomainSpoofing) {
    riskScore = Math.max(riskScore, 78);
    decisionBasis = 'subdomain_spoofing_detected';
  }

  if (intel.impersonatedBrand && (heuristic.signals.domainAge ?? 0) > 0) {
    riskScore = Math.max(riskScore, (heuristic.signals.suspiciousTLD ?? 0) > 0 ? 88 : 82);
    decisionBasis = 'brand_impersonation_detected';
  }

  if (reputation.reputationStatus === 'known_safe' && riskScore < 50 && !punycodeOrHomoglyph && !strongPhishing) {
    riskScore = Math.min(riskScore, 15);
    decisionBasis = 'known_safe_reputation';
  }

  const capped = clamp(riskScore, 0, 100);
  const riskLevel = toRiskLevel(capped);
  const recommendedAction =
    capped >= 76 ? 'block'
      : capped >= 26 ? 'warn'
        : 'allow';

  return {
    riskScore: capped,
    riskLevel,
    recommendedAction,
    confidence: calculateBaseConfidence(intel, heuristic, reputation),
    decisionBasis,
    signalsUsed
  };
}
