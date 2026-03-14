# @entropy-firewall/sdk

Official TypeScript SDK for the Entropy LLM Security Firewall.

## Installation

```bash
npm install @entropy-firewall/sdk
# or
pnpm add @entropy-firewall/sdk
# or
yarn add @entropy-firewall/sdk
```

## Quick Start

```typescript
import { EntropyClient } from '@entropy-firewall/sdk';

const client = new EntropyClient({
  apiUrl: 'http://localhost:8000',
  apiKey: 'ent-change-this-in-production'
});

async function run() {
  // Simple chat completion with OpenAI
  const response = await client.chatC({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: 'What is Entropy?' }],
    provider: 'openai'
  });
  
  console.log(response.choices[0].message.content);
  
  if (response.entropy_verdict.status === 'blocked') {
    console.warn(`Request was blocked! Threat: ${response.entropy_verdict.threat_level}`);
  }
}

run();
```

## Features

- **Multi-Provider Support**: Seamlessly route to OpenAI, Anthropic, Google, Groq, or OpenRouter via the `provider` param.
- **Streaming DLP**: Use `stream: true` to get real-time PII/code redaction.
- **Canary Tokens**: Extract leaked system prompts with the `extractSystemPrompt()` helper.
- **Security Feedback**: Submit user feedback using `await client.submitFeedback(...)` to train the engine.

## Documentation

Full documentation is available at [docs.entropy.security](https://docs.entropy.security).
