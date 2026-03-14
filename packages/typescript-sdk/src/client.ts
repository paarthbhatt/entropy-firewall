/**
 * Main Entropy Client.
 */

import {
  ChatCompletionRequest,
  ChatCompletionResponse,
  AnalyzeRequest,
  AnalyzeResponse,
  FeedbackRequest,
  FeedbackResponse,
  PatternStats,
} from './types';
import { EntropyError, EntropyBlockedError, EntropyRateLimitError } from './errors';

export interface EntropyConfig {
  baseUrl: string;
  apiKey: string;
  timeout?: number;
  provider?: string; // Override provider (openai, anthropic, google, groq, openrouter)
}

export class EntropyClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;
  private provider?: string;

  constructor(config: EntropyConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 30000;
    this.provider = config.provider;
  }

  /**
   * Chat completions - OpenAI compatible interface.
   */
  get chat() {
    return {
      completions: {
        create: async (request: ChatCompletionRequest): Promise<ChatCompletionResponse> => {
          return this.request('/v1/chat/completions', request);
        },
      },
    };
  }

  /**
   * Analyze text for security threats.
   */
  async analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
    return this.request('/v1/analyze', request);
  }

  /**
   * Submit feedback on a security decision.
   */
  async feedback(request: FeedbackRequest): Promise<FeedbackResponse> {
    return this.request('/v1/feedback', request);
  }

  /**
   * Get pattern statistics.
   */
  async getPatternStats(patternName?: string): Promise<PatternStats | PatternStats[]> {
    const endpoint = patternName
      ? `/v1/feedback/patterns/${patternName}/stats`
      : '/v1/feedback/patterns';
    return this.request(endpoint);
  }

  /**
   * Get recent feedback.
   */
  async getRecentFeedback(limit = 100, offset = 0): Promise<FeedbackResponse[]> {
    return this.request(`/v1/feedback/recent?limit=${limit}&offset=${offset}`);
  }

  /**
   * Make a request to the Entropy API.
   */
  private async request<T>(endpoint: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-API-Key': this.apiKey,
    };

    if (this.provider) {
      headers['X-Entropy-Provider'] = this.provider;
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: body ? 'POST' : 'GET',
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));

      if (response.status === 403 && error.entropy) {
        throw new EntropyBlockedError(
          error.detail || 'Request blocked by Entropy',
          error.entropy,
        );
      }

      if (response.status === 429) {
        throw new EntropyRateLimitError(
          error.detail || 'Rate limit exceeded',
          response.headers.get('Retry-After'),
        );
      }

      throw new EntropyError(
        error.detail || `HTTP ${response.status}`,
        response.status,
      );
    }

    return response.json();
  }
}

// Default export
export default EntropyClient;