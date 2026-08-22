export type PerturbationType =
  | "vowel_deletion"
  | "adjacent_swap"
  | "number_substitution"
  | "repeated_chars"
  | "whitespace_manipulation"
  | "phonetic_transliteration"
  | "hinglish_synthesis"
  | "mixed_scripts"
  | "punctuation_insertion"
  | "informal_abbreviations"
  | "unicode_confusables"
  | "zero_width_chars"
  | "unicode_normalization"
  | "multilingual_switching"
  | "nested_obfuscation"
  | "ocr_corruption"
  | "realistic_typos"
  | "domain_obfuscation"
  | "sender_id_mutation";

export interface PlaygroundRequest {
  message: string;
  perturbations?: PerturbationType[];
  intensity?: "low" | "medium" | "high" | "extreme";
  seed?: number;
}

export interface VariantEvaluation {
  variant_id: string;
  variant_text: string;
  perturbation_type: PerturbationType;
  perturbation_name: string;
  predicted_scam_family: string;
  risk_score: number;
  risk_level: string;
  confidence: number;
  is_detected_as_scam: boolean;
  cleaned_text: string;
}

export interface PlaygroundResponse {
  original_message: string;
  baseline_scam_family: string;
  baseline_risk_score: number;
  total_variants: number;
  detected_variants: number;
  robustness_score: number;
  variants: VariantEvaluation[];
}

export interface RedTeamIterationStep {
  iteration: number;
  depth: number;
  variant_text: string;
  perturbations_applied: string[];
  risk_score: number;
  is_detected: boolean;
  detected_scam_family: string;
  failure_identified?: string;
}

export interface ConfusionMatrix {
  true_positive: number;
  false_positive: number;
  true_negative: number;
  false_negative: number;
}

export interface RedTeamEvaluationReport {
  original_message: string;
  baseline_risk_score: number;
  total_mutations_tested: number;
  robustness_score: number;
  per_transformation_score: Record<string, number>;
  per_language_score: Record<string, number>;
  confusion_matrix: ConfusionMatrix;
  failure_examples: string[];
  hardest_examples: RedTeamIterationStep[];
  iteration_history: RedTeamIterationStep[];
}
