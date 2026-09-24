/**
 * Strongly typed domain data contracts mirroring FastAPI schemas exactly.
 * Zero-hallucination policy: no mock fallbacks, unknown is preserved.
 */

export interface CaptureResponseDTO {
  capture_id: string;
  capture_source: string;
  capture_format: string;
  original_filename: string | null;
  file_size_bytes: number;
  sha256: string;
  packet_count: number | null;
  duration_sec: number | null;
  first_packet_at: string | null;
  last_packet_at: string | null;
  link_layer_type: string | null;
  validation_state: string;
  created_at: string;
}

export interface AnalysisRunResponseDTO {
  analysis_id: string;
  capture_id: string;
  status: "QUEUED" | "RUNNING" | "PARTIAL" | "COMPLETED" | "FAILED" | "CANCELLED" | "NO_IPSEC";
  current_stage: string;
  parser_engine: string;
  parser_version: string;
  schema_version: string;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
}

export interface AnalysisListItemDTO {
  analysis_id: string;
  capture_id: string;
  capture_filename: string;
  capture_sha256: string;
  status: string;
  current_stage: string;
  created_at: string;
  completed_at: string | null;
  security_score: number | null;
  critical_findings: number;
  high_findings: number;
}

export interface ProtocolSummaryDTO {
  analysis_id: string;
  ipsec_detected: boolean;
  total_packets_inspected: number;
  ipsec_packet_count: number;
  ikev1_packet_count: number;
  ikev2_packet_count: number;
  esp_packet_count: number;
  ah_packet_count: number;
  nat_t_detected: boolean;
  observed_initiator_spis: string[];
  observed_responder_spis: string[];
  observed_cipher_suites: string[];
  observed_dh_groups: string[];
  observed_exchange_types: string[];
  evidence_states: Record<string, "VERIFIED" | "INFERRED" | "UNKNOWN" | "MISCONFIGURATION_OBSERVED">;
}

export interface ChildSecurityAssociationDTO {
  id: string;
  analysis_id: string;
  ike_sa_id: string | null;
  protocol: string;
  inbound_spi: string;
  outbound_spi: string;
  src_ip: string | null;
  dst_ip: string | null;
  mode: "TUNNEL" | "TRANSPORT" | "BEET" | "UNKNOWN";
  mode_evidence_state: string;
  encryption_algorithm: string | null;
  integrity_algorithm: string | null;
  pfs_status: "ENABLED" | "DISABLED" | "UNKNOWN";
  pfs_dh_group: string | null;
  pfs_evidence_state: string;
  first_observed_at: string | null;
  last_observed_at: string | null;
  lifecycle_state: string;
  evidence_state: string;
}

export interface SAGraphNodeDTO {
  id: string;
  type: string;
  label: string;
  data: Record<string, any>;
}

export interface SAGraphEdgeDTO {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface SAGraphResponseDTO {
  analysis_id: string;
  nodes: SAGraphNodeDTO[];
  edges: SAGraphEdgeDTO[];
}

export interface TrafficFlowItemDTO {
  flow_id: string;
  spi: string;
  reverse_spi: string | null;
  src_ip: string;
  dst_ip: string;
  duration_seconds: number;
  packet_count: number;
  byte_count: number;
  association_state: string;
  known_class: string | null;
  final_class: string | null;
  calibrated_confidence: number | null;
  normalized_entropy: number | null;
  ood_status: "KNOWN_ACCEPTED" | "ENTROPY_REJECTED" | "OUTLIER_REJECTED" | "INSUFFICIENT_LENGTH" | null;
  behavioral_anomaly_status: "NORMAL_BEHAVIOR" | "ANOMALOUS_BEHAVIOR" | null;
  top_shap_features: Array<{ feature: string; importance: number }> | null;
}

export interface TrafficSummaryResponseDTO {
  analysis_id: string;
  total_flows: number;
  classified_flows: number;
  classes_detected: string[];
  ood_count: number;
  anomaly_count: number;
  flows: TrafficFlowItemDTO[];
}

export interface ComplianceEvaluationDTO {
  rule_id: string;
  rule_title: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  standard: string;
  compliance_state: "PASS" | "FAIL" | "UNKNOWN" | "NOT_APPLICABLE";
  evidence_state: string;
  observed_value: any;
  expected_value: any;
  rationale: string;
}

export interface ComplianceSummaryDTO {
  analysis_id: string;
  profile_id: string;
  profile_name: string;
  policy_bundle_hash: string;
  total_evaluations: number;
  pass_count: number;
  fail_count: number;
  unknown_count: number;
  not_applicable_count: number;
  evaluations: ComplianceEvaluationDTO[];
}

export interface SecurityFindingDTO {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  category: string;
  score_deduction: number;
  affected_entity: string;
  technical_description: string;
  remediation_guidance: string;
  evidence_references: string[];
  evidence_state: string;
  root_cause_key: string;
}

export interface SecurityScoreDTO {
  analysis_id: string;
  overall_score: number;
  evidence_coverage: number;
  methodology_version: string;
  score_policy_hash: string;
  itemized_deductions: Record<string, number>;
  status: string;
}

export interface RiskAssessmentDTO {
  analysis_id: string;
  aggregate_risk_tier: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  risk_score: number;
  rationale: string;
}

export interface ThreatInstanceDTO {
  threat_id: string;
  title: string;
  category: string;
  likelihood: string;
  impact: string;
  risk_tier: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  mitre_technique_id: string;
  nist_control: string;
  evidence_state: string;
}

export interface FingerprintabilityDTO {
  analysis_id: string;
  overall_index: number;
  is_experimental: boolean;
  component_metrics: Record<string, number>;
  disclaimer: string;
}

export interface EvidenceGraphNodeDTO {
  id: string;
  node_type: string;
  label: string;
  entity_id: string;
  properties: Record<string, any>;
}

export interface EvidenceGraphEdgeDTO {
  source_id: string;
  target_id: string;
  relation_type: string;
}

export interface EvidenceGraphDTO {
  analysis_id: string;
  nodes: EvidenceGraphNodeDTO[];
  edges: EvidenceGraphEdgeDTO[];
  evidence_gaps?: Array<{ fact_name: string; rationale: string }>;
}

export interface AnalysisOverviewDTO {
  analysis_id: string;
  capture: {
    id: string | null;
    filename: string;
    sha256: string;
    file_size_bytes: number;
    packet_count: number;
  };
  analysis: {
    status: string;
    current_stage: string;
    parser_engine: string;
    parser_version: string;
    created_at: string | null;
    completed_at: string | null;
  };
  security_posture: {
    score: number;
    evidence_coverage: number;
    aggregate_risk_tier: string;
    itemized_deductions: Record<string, number>;
    methodology_version: string;
  };
  compliance_counts: {
    pass: number;
    fail: number;
    unknown: number;
    not_applicable: number;
  };
  findings_summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    top_findings: SecurityFindingDTO[];
  };
  traffic_summary: {
    classified_flows: number;
    classes_detected: string[];
    avg_calibrated_confidence: number | null;
    ood_count: number;
    anomaly_count: number;
  };
  fingerprintability: {
    overall_index: number;
    is_experimental: boolean;
    disclaimer: string;
  };
  protocol_summary: {
    total_observations: number;
    ike_versions: string[];
    protocols_detected: string[];
    nat_detected: boolean;
    transforms_observed: string[];
    dh_groups: string[];
  };
}

export interface ReportResponseDTO {
  id: string;
  analysis_id: string;
  report_type: "EXECUTIVE" | "TECHNICAL";
  status: "QUEUED" | "GENERATING" | "COMPLETED" | "PDF_FAILED_HTML_AVAILABLE" | "FAILED";
  format: "HTML" | "PDF" | "BOTH";
  template_version: string;
  engine_version: string;
  html_sha256: string | null;
  pdf_sha256: string | null;
  snapshot_manifest_sha256: string | null;
  generation_duration_ms: number | null;
  created_at: string;
  completed_at: string | null;
  error_message: string | null;
}

export interface ReportListResponseDTO {
  analysis_id: string;
  total_reports: number;
  items: ReportResponseDTO[];
}

export interface InterfaceMetadataDTO {
  interface_id: string;
  display_name: string;
  type: string;
  capture_allowed: boolean;
  lab_owned: boolean;
  operstate: string;
}
