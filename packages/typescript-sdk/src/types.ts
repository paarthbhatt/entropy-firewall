/**
 * TypeScript types for Entropy Firewall SDK.
 */

export type ThreatLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type EntropyStatus = 'allowed' | 'blocked' | 'sanitized';

export interface ThreatInfo {
  category: string;
  name: string;
  threat_level: ThreatLevel;
  confidence: number;
  details?: string;
  suggestion?: string;
}

export interface EntropyVerdict {
  status: EntropyStatus;
  confidence: number;
  threats_detected: ThreatInfo[];
  processing_time_ms: number;
  input_valid: boolean;
  output_sanitized?: boolean;
  suggestion?: string;
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | ChatMessageContent[];
  name?: string;
  tool_call_id?: string;
  tool_calls?: ToolCall[];
}

export interface ChatMessageContent {
  type: 'text' | 'image_url';
  text?: string;
  image_url?: { url: string };
}

export interface ToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
}

export interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  presence_penalty?: number;
  frequency_penalty?: number;
  stop?: string | string[];
  stream?: boolean;
  user?: string;
}

export interface ChatCompletionChoice {
  index: number;
  message: {
    role: string;
    content: string;
    tool_calls?: ToolCall[];
  };
  finish_reason: string;
}

export interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  entropy?: EntropyVerdict;
}

export interface AnalyzeRequest {
  text: string;
  history?: ChatMessage[];
}

export interface AnalyzeResponse extends EntropyVerdict {}

export interface FeedbackRequest {
  request_log_id?: number;
  pattern_name: string;
  category?: string;
  threat_level?: string;
  was_correct: boolean;
  expected_action?: 'allow' | 'block' | 'sanitize';
  reason?: string;
  confidence?: number;
  original_verdict?: string;
}

export interface FeedbackResponse {
  status: string;
  feedback_id: number;
  message: string;
}

export interface PatternStats {
  pattern_name: string;
  category?: string;
  total_feedback: number;
  correct_count: number;
  incorrect_count: number;
  accuracy_percentage: number;
  avg_confidence: number;
  last_feedback_at?: string;
}