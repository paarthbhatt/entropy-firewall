# Render Environment Variables (Entropy Firewall)

Use these in Render -> Service -> Environment.

## Required

- `ENTROPY_ENVIRONMENT=production`
- `ENTROPY_DEBUG=false`
- `ENTROPY_ENABLE_YAML_CONFIG=false`
- `ENTROPY_ENFORCE_DEPENDENCIES=true`
- `ENTROPY_MASTER_API_KEY=<generate-strong-key>`
- `ENTROPY_CORS_ORIGINS=["https://<your-vercel-domain>"]`

- `ENTROPY_DB_HOST=<your-supabase-host>`
- `ENTROPY_DB_PORT=5432`
- `ENTROPY_DB_NAME=postgres`
- `ENTROPY_DB_USER=postgres`
- `ENTROPY_DB_PASSWORD=<your-supabase-db-password>`

- `ENTROPY_REDIS_URL=<your-upstash-redis-url>`

- `OPENAI_API_KEY=<provider-key>`
- `OPENAI_BASE_URL=<provider-openai-compatible-base-url>`

### For Gemini AI Studio (OpenAI-compatible)

- `OPENAI_API_KEY=AIza...`
- `OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai`

## Recommended Optional

- `SENTRY_DSN=<your-sentry-dsn>`
- `SENTRY_ENVIRONMENT=production`
- `SENTRY_TRACES_SAMPLE_RATE=0.1`

- `POSTHOG_API_KEY=<your-posthog-project-key-or-ingest-key>`
- `POSTHOG_HOST=https://us.i.posthog.com`

- `PINECONE_API_KEY=<your-pinecone-api-key>`
- `PINECONE_ENVIRONMENT=<your-pinecone-env-or-serverless-region>`
- `PINECONE_INDEX=<your-index-name>`

## Build/Start

- Build command: `pip install -e .`
- Start command: `python -m uvicorn entropy.api.app:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`
