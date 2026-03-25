import { initEmailExtractor } from './emailExtractor'

/**
 * Initialize invisible email extraction and phishing analysis hooks.
 */
export function initEmailMlIntegration(): void {
  initEmailExtractor()
}
