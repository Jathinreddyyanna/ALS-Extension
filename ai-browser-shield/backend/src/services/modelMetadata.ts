import fs from 'fs'
import path from 'path'

/**
 * Model metadata containing training details, performance metrics, and feature importance
 */
export interface ModelMetadata {
  model_version: string
  model_type: string
  status: string
  trained_date: string
  model_file: string
  dataset_size: number
  n_estimators: number
  max_depth: number
  feature_names: string[]
  dataset_breakdown: {
    total_urls_loaded: number
    balanced_dataset_size: number
    benign_samples: number
    malicious_samples: number
    balance_ratio: string
  }
  training_split: {
    train_samples: number
    test_samples: number
    split_ratio: string
    train_benign: number
    train_malicious: number
    test_benign: number
    test_malicious: number
  }
  performance_metrics: {
    train_accuracy: number
    test_accuracy: number
    accuracy: number
    precision: number
    recall: number
    f1_score: number
    roc_auc: number
    auc_score: number
    false_positive_rate: number
    false_negative_rate: number
  }
  confusion_matrix: {
    true_negatives: number
    true_positives: number
    false_positives: number
    false_negatives: number
  }
  feature_importance: Record<string, number>
  feature_insights: Record<string, string>
  critical_discovery: string
  risk_thresholds: {
    low: { min: number; max: number; label: string }
    medium: { min: number; max: number; label: string }
    high: { min: number; max: number; label: string }
    critical: { min: number; max: number; label: string }
  }
  scoring_formula: {
    hybrid_score: string
    weights: { heuristic: number; ml_model: number }
    description: string
  }
  validation_notes: string
}

let modelMetadata: ModelMetadata | null = null

/**
 * Load model metadata from JSON file
 * Called on backend startup to cache model information
 * 
 * @returns The loaded metadata object
 * @throws Error if metadata file not found or invalid JSON
 */
export function loadModelMetadata(): ModelMetadata {
  try {
    const metadataPath = path.join(__dirname, '../../models/model_metadata.json')
    
    if (!fs.existsSync(metadataPath)) {
      throw new Error(`Model metadata file not found: ${metadataPath}`)
    }

    const fileContent = fs.readFileSync(metadataPath, 'utf-8')
    modelMetadata = JSON.parse(fileContent) as ModelMetadata

    console.log(
      `✓ Model metadata loaded: v${modelMetadata.model_version} ` +
      `(${modelMetadata.dataset_size.toLocaleString()} samples, ` +
      `${(modelMetadata.performance_metrics.accuracy * 100).toFixed(2)}% accuracy)`
    )

    return modelMetadata
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error(`✗ Failed to load model metadata: ${message}`)
    throw error
  }
}

/**
 * Get cached model metadata
 * Returns the previously loaded metadata without re-reading from disk
 * 
 * @returns The cached metadata object or null if not yet loaded
 */
export function getModelMetadata(): ModelMetadata | null {
  return modelMetadata
}

/**
 * Get model performance summary for logging
 * Provides a human-readable summary of model performance
 * 
 * @returns Formatted performance summary
 */
export function getModelPerformanceSummary(): string {
  if (!modelMetadata) {
    return 'Model metadata not loaded'
  }

  const m = modelMetadata.performance_metrics
  const dataset = modelMetadata.dataset_breakdown

  return (
    `Model Performance Summary:\n` +
    `  Version: ${modelMetadata.model_version}\n` +
    `  Dataset: ${dataset.balanced_dataset_size.toLocaleString()} URLs (balanced)\n` +
    `  Train/Test Split: ${modelMetadata.training_split.split_ratio}\n` +
    `  Accuracy: ${(m.accuracy * 100).toFixed(2)}%\n` +
    `  Precision: ${(m.precision * 100).toFixed(2)}% (low false alarm rate)\n` +
    `  Recall: ${(m.recall * 100).toFixed(2)}% (catches ${(m.recall * 100).toFixed(1)}% of threats)\n` +
    `  F1-Score: ${(m.f1_score * 100).toFixed(2)}%\n` +
    `  ROC-AUC: ${(m.roc_auc * 100).toFixed(2)}% (excellent discrimination)\n` +
    `  Status: ${modelMetadata.status}`
  )
}

/**
 * Get top feature importance features
 * Returns the most important features ranked by importance
 * 
 * @param limit - Maximum number of features to return (default: 5)
 * @returns Array of features sorted by importance (highest first)
 */
export function getTopFeatures(limit = 5): Array<{ name: string; importance: number; insight: string }> {
  if (!modelMetadata) return []

  return Object.entries(modelMetadata.feature_importance)
    .map(([name, importance]) => ({
      name,
      importance,
      insight: modelMetadata?.feature_insights[name] || 'No insight available',
    }))
    .sort((a, b) => b.importance - a.importance)
    .slice(0, limit)
}

/**
 * Validate model metadata integrity
 * Checks that all required fields are present and metrics are in valid ranges
 * 
 * @returns Object with validation results
 */
export function validateModelMetadata(): { valid: boolean; issues: string[] } {
  const issues: string[] = []

  if (!modelMetadata) {
    return { valid: false, issues: ['Model metadata not loaded'] }
  }

  // Check required fields
  const requiredFields = [
    'model_version',
    'dataset_size',
    'feature_importance',
    'performance_metrics',
    'risk_thresholds',
  ]
  for (const field of requiredFields) {
    if (!(field in modelMetadata)) {
      issues.push(`Missing required field: ${field}`)
    }
  }

  // Validate metric ranges
  const { accuracy, precision, recall, roc_auc } = modelMetadata.performance_metrics
  if (accuracy < 0 || accuracy > 1) issues.push(`Invalid accuracy: ${accuracy}`)
  if (precision < 0 || precision > 1) issues.push(`Invalid precision: ${precision}`)
  if (recall < 0 || recall > 1) issues.push(`Invalid recall: ${recall}`)
  if (roc_auc < 0 || roc_auc > 1) issues.push(`Invalid ROC-AUC: ${roc_auc}`)

  // Validate feature importance sums to ~1.0
  const importanceSum = Object.values(modelMetadata.feature_importance).reduce((a, b) => a + b, 0)
  if (Math.abs(importanceSum - 1.0) > 0.01) {
    issues.push(`Feature importance sum is ${importanceSum.toFixed(4)}, expected ~1.0`)
  }

  return { valid: issues.length === 0, issues }
}
