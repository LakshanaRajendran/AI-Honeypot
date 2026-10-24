/**
 * TypeScript Data Models and Schema Definitions for the
 * AI-Driven Adaptive Deception Mesh Operations Dashboard.
 */

export interface FeatureProvenance {
  [featureName: string]: "observed_telemetry" | "temporal_calculation" | "lexical_pattern" | "heuristic_enrichment";
}

export interface RawFeatures {
  total_events: number;
  command_count: number;
  unique_commands: number;
  unique_processes: number;
  unique_mitre_tactics: number;
  unique_mitre_techniques: number;
  session_duration_seconds: number;
  mean_inter_event_seconds: number;
  std_inter_event_seconds: number;
  min_inter_event_seconds: number;
  max_inter_event_seconds: number;
  commands_per_minute: number;
  network_utility_ratio: number;
  file_inspection_ratio: number;
  identity_command_ratio: number;
  credential_keyword_ratio: number;
  download_utility_ratio: number;
  mean_risk_score: number;
  max_risk_score: number;
  risk_score_std: number;
  high_or_critical_ratio: number;
  path_command_ratio: number;
  pipe_ratio: number;
  redirect_ratio: number;
  mean_command_length: number;
  mean_argument_count: number;
}

export interface ShapContribution {
  feature_name: string;
  shap_value: number;
  direction: "supports_weaponized_intrusion" | "opposes_weaponized_intrusion";
}

export interface ShapExplanation {
  model_explained: string;
  explainer: string;
  top_features: ShapContribution[];
  interpretation_note: string;
}

export interface FeatureDeviation {
  feature_name: string;
  observed_value: number;
  reference_mean: number;
  reference_std: number;
  deviation_score: number;
  description: string;
}

export interface BinaryClassification {
  predicted_class: 0 | 1;
  predicted_label: "low_interaction_probe" | "weaponized_intrusion";
  confidence: number;
  classification_basis: string;
}

export interface IntentScores {
  reconnaissance: number;
  execution: number;
  persistence: number;
  defense_evasion: number;
}

export interface IntentPrediction {
  detected_intents: string[];
  intent_scores: IntentScores;
  unsupported_intents: string[];
  intent_basis: string;
}

export interface Module3Prediction {
  session_id: string;
  classification: BinaryClassification;
  intent: IntentPrediction;
  anomaly?: any;
  explanations?: FeatureDeviation[];
  shap_explanation?: ShapExplanation;
  label_provenance?: string;
  limitations: string[];
}

export interface Module4Decision {
  schema_version: string;
  engine_version: string;
  session_id: string;
  threat_level: "low" | "medium" | "high" | "undetermined";
  source_classification_confidence: number | null;
  detected_intent_used: string | null;
  selected_strategy: string;
  decision_basis: string[];
  requires_execution_layer: boolean;
  execution_status: string;
  execution_note: string;
}

export interface Module4Simulation {
  session_id: string;
  adapter_version: string;
  execution_mode: "simulation_only";
  applied_to_cowrie: boolean;
  commands_executed: boolean;
  timestamp: string;
  requested_strategy: string;
  status: "simulated_only" | "rejected";
  reason: string;
  simulated_profile: string | null;
}

export interface SessionReport {
  session_id: string;
  source_ips: string[];
  event_count: number;
  commands_observed: string[];
  feature_provenance: FeatureProvenance;
  raw_features: RawFeatures;
  module3_prediction: Module3Prediction;
  module4_decision: Module4Decision;
  module4_simulation: Module4Simulation;
}

export interface DemoDataset {
  report_version: string;
  mode: string;
  source_log_directory: string;
  source_log_files: string[];
  command_events_processed: number;
  sessions_processed: number;
  safety: {
    commands_executed: boolean;
    cowrie_configuration_changed: boolean;
    deception_response_executed: boolean;
    module4_execution_status: string;
    live_deception_applied: boolean;
  };
  limitations: string[];
  sessions: SessionReport[];
}

export interface ArtifactStatus {
  exists: boolean;
  expected_sha256: string;
  actual_sha256: string | null;
  valid: boolean;
  path: string;
}

export interface SystemHealth {
  status: "healthy" | "degraded";
  timestamp: string;
  artifacts_intact: boolean;
  artifacts: { [filename: string]: ArtifactStatus };
  cowrie_logs: {
    directory_exists: boolean;
    directory_path: string;
    log_files_count: number;
    log_files: string[];
  };
  latest_report: {
    exists: boolean;
    path: string;
    last_modified: string | null;
  };
  safety_guarantees: {
    simulation_only: boolean;
    no_live_commands_executed: boolean;
    no_cowrie_config_changes: boolean;
    localhost_binding_only: boolean;
    frozen_model_and_scaler: boolean;
  };
  disclosures: string[];
  pipeline_state: {
    last_run_timestamp: string | null;
    last_status: string;
    stdout: string;
    stderr: string;
  };
}

export interface DocumentationPayload {
  title: string;
  file_path: string;
  headings: string[];
  content_markdown: string;
}

export type ScenarioType = "all" | "reconnaissance" | "suspicious" | "fallback";
