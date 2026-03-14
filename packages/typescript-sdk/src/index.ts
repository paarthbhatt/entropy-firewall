/**
 * Entropy Firewall TypeScript SDK
 *
 * OpenAI-compatible client with built-in security analysis.
 */

export { EntropyClient, EntropyConfig } from './client';
export { analyze, chat } from './api';
export type {
  ChatCompletionRequest,
  ChatCompletionResponse,
  EntropyVerdict,
  ThreatInfo,
  ThreatLevel,
  EntropyStatus,
  AnalyzeRequest,
  AnalyzeResponse,
} from './types';
export { EntropyError, EntropyBlockedError, EntropyRateLimitError } from './errors';