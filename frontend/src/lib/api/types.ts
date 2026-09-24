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

export interface SemanticDiffItemDTO {
  field: string;
  label: string;
  current_value: any;
  current_evidence_state: string;
  proposed_value: any;
  is_changed: boolean;
  policy_impact: string;
}

export interface ProjectedFindingDTO {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  root_cause_key: string;
  projected_state: string;
  rationale: string;
}

export interface ProjectedRegressionAuditDTO {
  targeted_finding_ids: string[];
  targeted_rule_ids: string[];
  projected_resolved_findings: ProjectedFindingDTO[];
  projected_remaining_findings: ProjectedFindingDTO[];
  projected_new_regressions: ProjectedFindingDTO[];
  baseline_score: number | null;
  projected_score: number | null;
  projected_score_delta: number | null;
  baseline_risk_score: number | null;
  projected_risk_score: number | null;
  projected_risk_delta: number | null;
  has_blocking_regressions: boolean;
  proof_obligations: any[];
  disclaimer: string;
}

export interface TwinResponseDTO {
  twin_id: string;
  analysis_id: string;
  status: string;
  proposal_hash: string;
  current_snapshot: Record<string, any>;
  proposed_ir: Record<string, any>;
  rendered_proposed_config: string;
  semantic_diff: SemanticDiffItemDTO[];
  text_diff: string;
  projected_regression_audit: ProjectedRegressionAuditDTO;
  projected_score: number | null;
  projected_score_delta: number | null;
  disclaimer: string;
}

export interface PreflightCheckDTO {
  code: string;
  status: "PASS" | "FAIL" | "WARN";
  message: string;
}

export interface PreflightResponseDTO {
  status: "READY" | "BLOCKED" | "WARNING";
  is_ready: boolean;
  checks: PreflightCheckDTO[];
  blocking_reasons: string[];
}

export interface RemediationRunStepDTO {
  sequence: number;
  action_type: string;
  status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILED" | "SKIPPED";
  safe_output: Record<string, any> | null;
  error_code: string | null;
  created_at: string;
}

export interface RemediationRunResponseDTO {
  run_id: string;
  twin_id: string;
  status: string;
  proposal_hash: string;
  lab_instance_id: string;
  operator_id: string;
  rollback_state: string;
  rollback_reason: string | null;
  error_message: string | null;
  steps: RemediationRunStepDTO[];
  executed_at: string;
  completed_at: string | null;
}

export interface VerificationClaimDTO {
  claim_id: string;
  rule_id: string;
  rule_version: string;
  root_cause_key: string;
  claim_result: "VERIFIED_RESOLVED" | "VERIFIED_NOT_RESOLVED" | "PARTIALLY_VERIFIED" | "UNKNOWN" | "NOT_APPLICABLE";
  reason_code: string;
  expected_condition: string | null;
  baseline_evidence: Record<string, any> | null;
  post_evidence: Record<string, any> | null;
}

export interface VerificationResponseDTO {
  verification_id: string;
  remediation_run_id: string;
  baseline_analysis_id: string;
  post_analysis_id: string | null;
  post_capture_id: string | null;
  verification_result: "VERIFIED_RESOLVED" | "VERIFIED_NOT_RESOLVED" | "PARTIALLY_VERIFIED" | "VERIFICATION_FAILED" | "UNKNOWN";
  security_result: "RESOLVED" | "NOT_RESOLVED" | "PARTIAL" | "UNKNOWN" | "FAILED";
  operational_result: "HEALTHY" | "DEGRADED" | "FAILED";
  baseline_score: number | null;
  verified_score: number | null;
  score_delta: number | null;
  claims: VerificationClaimDTO[];
  finding_diff_summary: Record<string, any> | null;
  regression_summary: Record<string, any> | null;
  verified_at: string;
}

// -----------------------------------------------------------------------------
// Stage 11: Grounded AI Analyst & Local RAG Types
// -----------------------------------------------------------------------------

export interface AIChatClaimDTO {
  claim_id: string;
  text: string;
  claim_type: "PROTOCOL_FACT" | "POLICY_FINDING" | "SECURITY_SCORE" | "ML_INFERENCE" | "STANDARD_REQUIREMENT" | "REMEDIATION_STATUS";
  epistemic_state: "VERIFIED" | "INFERRED" | "UNKNOWN" | "PROJECTED" | "VERIFIED_POST_REMEDIATION";
  citation_ids: string[];
}

export interface AIChatCitationDTO {
  source_id: string;
  source_type: "fact" | "finding" | "rule" | "score" | "flow" | "standard" | "twin" | "verification" | "claim";
  locator: string;
  title: string;
  excerpt?: string;
}

export interface AIChatQueryResponseDTO {
  query_run_id: string;
  session_id: string;
  analysis_id: string;
  status: "ANSWERED" | "INSUFFICIENT_EVIDENCE" | "OUT_OF_SCOPE" | "MODEL_UNAVAILABLE" | "FAILED";
  answer: string;
  claims: AIChatClaimDTO[];
  citations: AIChatCitationDTO[];
  limitations: string[];
  provenance: {
    answer_hash: string;
    fact_lock_hash: string;
    prompt_template_version: string;
    model_name: string;
    verified_at: string;
  } | null;
  metrics: {
    generation_ms?: number;
    total_ms: number;
    citation_validity_rate?: number;
    prompt_eval_count?: number;
    eval_count?: number;
  };
}

export interface AIChatMessageDTO {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  status: string;
  claims: AIChatClaimDTO[] | null;
  citations: AIChatCitationDTO[] | null;
  limitations: string[] | null;
  created_at: string;
}

export interface AIChatSessionHistoryDTO {
  session_id: string;
  analysis_id: string | null;
  title: string;
  model_name: string;
  is_active: boolean;
  messages: AIChatMessageDTO[];
}

export interface EvidenceSearchResponseDTO {
  analysis_id: string;
  query: string;
  intent: string;
  fact_lock_hash: string;
  matched_facts: Array<{
    source_id: string;
    fact_type: string;
    name: string;
    value: any;
    epistemic_state: string;
    entity: string;
  }>;
  matched_standards: Array<{
    source_id: string;
    document_code: string;
    section_reference: string;
    section_title: string;
    authority: string;
    similarity: number;
    excerpt: string;
  }>;
}

export interface AIHealthResponseDTO {
  status: "healthy" | "degraded" | "offline";
  runtime: string;
  base_url: string;
  primary_model: string;
  primary_model_available: boolean;
  fallback_model: string;
  fallback_model_available: boolean;
  embedding_model: string;
  embedding_model_available: boolean;
  embedding_dimension: number;
  knowledge_index_ready: boolean;
  total_documents_indexed: number;
  total_chunks_indexed: number;
  installed_models: string[];
}

export interface DiscoveredServiceDTO {
  id: string;
  protocol: string;
  port: number;
  state: string;
  state_reason: string | null;
  service_name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  confidence: number | null;
}

export interface DiscoveredHostDTO {
  id: string;
  ip_address: string;
  ip_version: string;
  state: string;
  hostnames: string[] | null;
  services: DiscoveredServiceDTO[];
}

export interface DiscoveryJobDTO {
  id: string;
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  authorization_attestation: string;
  authorized_at: string;
  profile: string;
  requested_targets: string[];
  canonical_targets: string[];
  exclusions: string[];
  permitted_ports: number[];
  status:
    | "QUEUED"
    | "VALIDATING"
    | "RUNNING"
    | "COMPLETED"
    | "COMPLETED_WITH_AMBIGUITY"
    | "CANCELLED"
    | "FAILED"
    | "REJECTED"
    | "TOOL_UNAVAILABLE";
  failure_reason: string | null;
  raw_output_sha256: string | null;
  output_bytes_count: number | null;
  tool_version: string | null;
  target_count: number;
  hosts_up_count: number;
  services_discovered_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  hosts: DiscoveredHostDTO[];
}

export interface DiscoveryStatusDTO {
  enabled: boolean;
  nmap_available: boolean;
  nmap_version: string | null;
  nmap_path: string | null;
  max_targets: number;
  max_ports: number;
  timeout_sec: number;
  rate_limit_pps: number;
  available_profiles: Array<{ name: string; description: string; protocol: string }>;
}

export interface DiscoveryJobCreateRequestDTO {
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  authorization_attestation: string;
  profile: string;
  requested_targets: string[];
  exclusions?: string[];
  permitted_ports?: number[];
}

export interface IkeAssessmentStatusDTO {
  enabled: boolean;
  ike_scan_available: boolean;
  ike_scan_version: string | null;
  ike_scan_path: string | null;
  timeout_sec: number;
  allow_experimental_v2: boolean;
  available_profiles: Array<{
    name: string;
    description: string;
    ike_version: string;
    is_experimental: boolean;
    default_port: number;
    permitted_ports: number[];
    retries: number;
    timeout_ms: number;
  }>;
}

export interface IkeProbeResultDTO {
  id: string;
  target_ip: string;
  target_port: number;
  response_category: string;
  ike_version: string;
  handshake_type: string | null;
  notify_code: number | null;
  notify_message: string | null;
  vendor_ids: string[] | null;
  transforms_returned: Array<Record<string, any>> | null;
  rtt_ms: number | null;
  is_experimental: boolean;
  created_at: string;
}

export interface IkeJobResponseDTO {
  id: string;
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  target_ip: string;
  target_port: number;
  profile: string;
  ike_version_requested: string;
  status:
    | "QUEUED"
    | "VALIDATING"
    | "RUNNING"
    | "COMPLETED"
    | "CANCELLED"
    | "FAILED"
    | "TOOL_UNAVAILABLE";
  failure_reason: string | null;
  raw_output_sha256: string | null;
  output_bytes_count: number | null;
  tool_version: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  results: IkeProbeResultDTO[];
}

export interface IkeJobCreateRequestDTO {
  job_name: string;
  operator_id: string;
  authorization_reference: string;
  authorization_attestation: string;
  profile_name: string;
  target: string;
  port?: number;
  analysis_id?: string;
}

export interface IkeConcordanceDTO {
  id: string;
  analysis_id: string;
  ike_job_id: string | null;
  target_ip: string;
  concordance_status:
    | "CONSISTENT"
    | "CONFLICT"
    | "INSUFFICIENT_EVIDENCE"
    | "NOT_COMPARABLE";
  passive_ike_versions: string[];
  active_ike_versions: string[];
  passive_selected_cipher: string | null;
  active_accepted_cipher: string | null;
  concordance_details: {
    passive_lane?: {
      ike_versions: string[];
      selected_cipher: string | null;
      associated_frames: number[];
      has_initial_negotiation: boolean;
    };
    active_lane?: {
      ike_versions: string[];
      accepted_cipher: string | null;
      response_categories: string[];
      is_experimental: boolean;
      rtt_ms: number | null;
    };
    lab_ground_truth_lane?: any;
  };
  evaluated_at: string;
}


