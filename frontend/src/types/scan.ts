export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface ScanSummary {
  id: string;
  target_path: string;
  status: string;
  scanned_files_count: number;
  scanned_lines_count: number;
  total_findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  duration_ms: number;
  created_at: string;
}

export interface AIExplanation {
  summary: string;
  root_cause: string;
  why_dangerous: string;
  potential_impact: string;
  recommended_fix: string;
  secure_example: string;
  provider_name: string;
  model_name: string;
  is_ai_generated: boolean;
}

export interface Finding {
  id?: string;
  scan_id?: string;
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  language: string;
  file_path: string;
  line_number: number;
  column_number: number;
  end_line: number;
  code_snippet: string;
  message: string;
  confidence: number;
  owasp_category: string;
  recommendation: string;
  references?: string[];
  fingerprint: string;
  detection_source: string;
  ai_explanation?: AIExplanation;
}



export interface ScanReport {
  summary: ScanSummary;
  findings: Finding[];
  parser_errors: string[];
}

export interface RuleMetadata {
  rule_id: string;
  name: string;
  description: string;
  language: string;
  severity: SeverityLevel;
  owasp_category: string;
  confidence: number;
  recommendation: string;
  references: string[];
}
