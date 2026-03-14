/**
 * Convenience API methods.
 */

import { EntropyClient } from './client';
import type {
  ChatCompletionRequest,
  ChatCompletionResponse,
  AnalyzeRequest,
  AnalyzeResponse,
} from './types';

let defaultClient: EntropyClient | null = null;

/**
 * Initialize the default client.
 */
export function init(config: { baseUrl: string; apiKey: string; provider?: string }): void {
  defaultClient = new EntropyClient(config);
}

/**
 * Get the default client or throw if not initialized.
 */
function getClient(): EntropyClient {
  if (!defaultClient) {
    throw new Error('Entropy SDK not initialized. Call init() first.');
  }
  return defaultClient;
}

/**
 * Chat completions API.
 */
export const chat = {
  completions: {
    /**
     * Create a chat completion.
     */
    create: async (request: ChatCompletionRequest): Promise<ChatCompletionResponse> => {
      return getClient().chat.completions.create(request);
    },
  },
};

/**
 * Analyze text for security threats.
 */
export async function analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
  return getClient().analyze(request);
}

/**
 * Quick security check for a text string.
 */
export async function checkText(text: string): Promise<{ safe: boolean; verdict: AnalyzeResponse }> {
  const verdict = await analyze({ text });
  return {
    safe: verdict.status === 'allowed' && verdict.threats_detected.length === 0,
    verdict,
  };
}