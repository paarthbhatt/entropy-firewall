# Entropy Firewall — Enterprise Edition Features

This directory contains the Enterprise features for the Entropy LLM Security Firewall. These features extend the core firewall with adaptive learning, persistent policy management, multi-provider routing, and document scanning.

## 🌟 New Capabilities

### 1. Multi-Provider Gateway
Route requests across OpenAI, Anthropic, Google Gemini, Groq, and OpenRouter with a unified API. Provider logic is decoupled via the `ProviderRegistry` making it easy to hot-swap models without changing client code.

```bash
# Example
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer my-key" \
  -H "X-Entropy-Provider: anthropic" \
  -d '{"model": "claude-3-opus-20240229", "messages": [{"role":"user", "content":"Hello"}]}'
```

### 2. Streaming DLP
The streaming output filter intercepts Server-Sent Events (SSE) and uses a sliding window (configurable up to 256 tokens) to redact PII and detect code injections _before_ they stream to the user, without breaking connection state.

### 3. Sentinel Canary Tokens
Inject invisible, high-entropy cryptographic strings into system prompts. If a user successfully jailbreaks the LLM and forces it to leak its prompt, Entropy detects the canary token in the output, terminates the stream instantly, and logs the breach attempt in Redis for auditing.

### 4. Continuous Learning Feedback Loop
Security policies are no longer static. You can submit feedback on whether a block/allow action was correct. The `ThresholdTuner` analyzes this feedback in Postgres and automatically adjusts pattern confidence thresholds to minimize false positives over time.

### 5. RAG Shield
Pre-scan embedded documents and vector database chunks for embedded prompt injections or context-poisoning attacks _before_ they are inserted into the context window. 

```javascript
// Scan documents
const scanResult = await client.ragScan({
  documents: [{ id: "doc_1", content: "..." }]
});
```

### 6. Hot-Reloadable Policies
Update regex patterns, security guardrails, and block actions via the Admin API. Changes are stored in PostgreSQL and broadcast to all replica instances via Redis Pub/Sub, updating in-memory rule engines with zero downtime.

## Configuration

Enable features via environment variables (see `.env.example`).
Ensure PostgreSQL 15+ and Redis 7+ are connected.

## Architecture

These features wire directly into the `entropy/api/app.py` lifespan and sit transparently inside the main `Chat` API route middleware stack.
