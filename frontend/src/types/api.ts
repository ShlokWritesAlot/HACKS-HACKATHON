/**
 * Shared API Types
 * 
 * Synchronized with the FastAPI backend Pydantic schemas.
 */

export type HealthStatus = "healthy" | "degraded" | "unhealthy";

export interface DatabaseHealth {
  status: HealthStatus;
  latency_ms?: number;
  error?: string;
}

export interface HealthResponse {
  status: HealthStatus;
  version: string;
  environment: string;
  uptime_seconds: number;
  request_id: string;
  database: DatabaseHealth;
}

export interface ManipulationFingerprint {
  fear: number;
  urgency: number;
  authority_impersonation: number;
  financial_request: number;
  credential_request: number;
  suspicious_link: number;
  call_to_action_pressure: number;
}

export interface AnalyzeResponse {
  analysis_id: string;
  risk_score: number;
  risk_level: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  scam_family: string;
  language: string;
  original_text: string;
  normalized_text: string;
  decoded_meaning: string;
  manipulation_fingerprint: ManipulationFingerprint;
  obfuscation_fingerprint: string[];
  evidence: string[];
  safe_action: string;
  model_version: string;
  extracted_iocs?: any[];
  brand_impersonation?: any;
  conversation_state?: any;
  scam_dna?: any;
}

export interface BatchAnalyzeResponse {
  results: AnalyzeResponse[];
  total_processed: number;
}

export interface FeedbackRequest {
  analysis_id: string;
  is_correct: boolean;
  comment?: string;
  analyst_id?: string;
}

export interface FeedbackResponse {
  feedback_id: string;
  analysis_id: string;
  status: string;
  recorded_at: string;
}

export interface ErrorDetail {
  field?: string;
  message: string;
}

export interface ErrorEnvelope {
  code: string;
  message: string;
  request_id: string;
  details: ErrorDetail[];
}

export interface ErrorResponse {
  error: ErrorEnvelope;
}
