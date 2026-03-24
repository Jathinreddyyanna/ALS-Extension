/**
 * Risk Color System
 * Color schemes and utilities for risk level visualization
 */

export interface RiskLevel {
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  color: string;
  bgColor: string;
  borderColor: string;
  textColor: string;
  emoji: string;
  label: string;
}

/**
 * Get risk level details based on risk score
 */
export function getRiskLevel(riskScore: number): RiskLevel {
  if (riskScore >= 80) {
    return {
      level: 'CRITICAL',
      color: '#DC2626',       // Red-600
      bgColor: '#FEE2E2',     // Red-100
      borderColor: '#EF4444', // Red-500
      textColor: '#991B1B',   // Red-800
      emoji: '🚨',
      label: 'Critical Threat'
    };
  } else if (riskScore >= 60) {
    return {
      level: 'HIGH',
      color: '#EA580C',       // Orange-600
      bgColor: '#FFEDD5',     // Orange-100
      borderColor: '#F97316', // Orange-500
      textColor: '#9A3412',   // Orange-800
      emoji: '⚠️',
      label: 'High Risk'
    };
  } else if (riskScore >= 30) {
    return {
      level: 'MEDIUM',
      color: '#CA8A04',       // Yellow-600
      bgColor: '#FEF3C7',     // Yellow-100
      borderColor: '#EAB308', // Yellow-500
      textColor: '#854D0E',   // Yellow-800
      emoji: '⚡',
      label: 'Suspicious'
    };
  } else if (riskScore >= 10) {
    return {
      level: 'LOW',
      color: '#059669',       // Emerald-600
      bgColor: '#D1FAE5',     // Emerald-100
      borderColor: '#10B981', // Emerald-500
      textColor: '#065F46',   // Emerald-800
      emoji: '✅',
      label: 'Low Risk'
    };
  } else {
    return {
      level: 'SAFE',
      color: '#16A34A',       // Green-600
      bgColor: '#D1FAE5',     // Green-100
      borderColor: '#22C55E', // Green-500
      textColor: '#166534',   // Green-800
      emoji: '✅',
      label: 'Safe'
    };
  }
}

/**
 * Get action label based on risk level
 */
export function getActionLabel(riskScore: number): string {
  if (riskScore >= 80) {
    return 'DELETE IMMEDIATELY';
  } else if (riskScore >= 60) {
    return 'DO NOT CLICK LINKS';
  } else if (riskScore >= 30) {
    return 'BE CAUTIOUS';
  } else {
    return 'APPEARS SAFE';
  }
}

/**
 * Get risk description
 */
export function getRiskDescription(riskScore: number, isPhishing: boolean): string {
  if (riskScore >= 80) {
    return 'Critical phishing threat detected. This email is extremely dangerous.';
  } else if (riskScore >= 60) {
    return 'High risk of phishing. Do not click any links or attachments.';
  } else if (riskScore >= 30) {
    return 'Suspicious email. Verify sender before taking any action.';
  } else if (isPhishing) {
    return 'Potential phishing detected but risk is low. Still be cautious.';
  } else {
    return 'Email appears to be legitimate.';
  }
}

/**
 * Color palette for charts/visualizations
 */
export const RISK_COLORS = {
  CRITICAL: '#DC2626',
  HIGH: '#EA580C',
  MEDIUM: '#CA8A04',
  LOW: '#059669',
  SAFE: '#16A34A',
};

/**
 * Gradient backgrounds for risk levels
 */
export const RISK_GRADIENTS = {
  CRITICAL: 'linear-gradient(135deg, #FEE2E2 0%, #FCA5A5 100%)',
  HIGH: 'linear-gradient(135deg, #FFEDD5 0%, #FDBA74 100%)',
  MEDIUM: 'linear-gradient(135deg, #FEF3C7 0%, #FDE047 100%)',
  LOW: 'linear-gradient(135deg, #D1FAE5 0%, #6EE7B7 100%)',
  SAFE: 'linear-gradient(135deg, #D1FAE5 0%, #86EFAC 100%)',
};
