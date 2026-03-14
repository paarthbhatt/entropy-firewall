/**
 * Entropy SDK error types.
 */

import type { EntropyVerdict } from './types';

/**
 * Base error class for Entropy SDK.
 */
export class EntropyError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
  ) {
    super(message);
    this.name = 'EntropyError';
  }
}

/**
 * Error thrown when a request is blocked by Entropy security analysis.
 */
export class EntropyBlockedError extends EntropyError {
  constructor(
    message: string,
    public verdict: EntropyVerdict,
  ) {
    super(message, 403);
    this.name = 'EntropyBlockedError';
  }
}

/**
 * Error thrown when rate limit is exceeded.
 */
export class EntropyRateLimitError extends EntropyError {
  constructor(
    message: string,
    public retryAfter?: string | null,
  ) {
    super(message, 429);
    this.name = 'EntropyRateLimitError';
  }
}