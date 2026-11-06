# Kavach hybrid deployment plan

## Deployment intent

Kavach has two user-facing deployments:

- **Vercel preview / build environment:** the PR-linked Vercel deployment is the first place to review the UI and integration changes. Its same-origin `/api/*` route is a thin Node serverless BFF.
- **AWS production:** CloudFront serves the production frontend. The existing AWS Node BFF, FastAPI control plane, Lambda, Step Functions, Fargate scanner, DynamoDB, S3, and Bedrock remain the authoritative execution plane.

The two URLs are separate release targets, not two independent databases or two independent security control planes.

## Request flow

```text
Browser
  |-- Vercel preview URL
  |     |-- static React app
  |     '-- /api/* -> Vercel serverless BFF -> AWS Node BFF -> AWS FastAPI / services
  |
  '-- AWS CloudFront URL
        '-- static React app -> AWS Node BFF -> AWS FastAPI / services

AWS control plane
  |-- Shield authorization -> deterministic capability checks + Cedar
  |-- workflow orchestration
  '-- artifact pipeline -> Step Functions -> scanners -> isolated Fargate sandbox

Advisory explanation provider
  |-- Primary: AWS Bedrock / Strands
  '-- Optional fallback: external OpenAI-compatible API, enabled explicitly
```

## Why the execution plane stays on AWS

The existing product uses process-level runtime/workflow registries, long-running agent workflows, Step Functions, Fargate, S3, DynamoDB, and Bedrock. Moving those services into short-lived Vercel functions would change their lifecycle and state semantics; it is not a safe lift-and-shift. The Vercel function added in this PR is intentionally a transport adapter, not a second authorization engine.

**Never fail over authorization to an LLM or a less restrictive policy.** If the authoritative Shield/Cedar control plane is unavailable, protected actions must fail closed.

## Token exhaustion fallback

The scanner's LLM is explanatory only. The deterministic scanner verdict is computed before the explanation step and remains authoritative.

An optional provider fallback has been added to `scanner/agent/scanner_agent.py`:

- Bedrock remains primary.
- An OpenAI-compatible endpoint is attempted only when `ENABLE_EXTERNAL_LLM_FALLBACK=true` and `OPENAI_API_KEY` are configured.
- The fallback receives read-only artifact metadata, findings, and the already-computed verdict.
- It cannot write findings, approve artifacts, change risk scores, authorize agents, or mutate security state.
- If both providers fail, the explanation is unavailable; the deterministic scan result remains available and unchanged.

Because this sends scan metadata to a third-party provider, enable it only after approving the data-handling implications. Store `OPENAI_API_KEY` in AWS Secrets Manager / the backend runtime secret store, never in Git or a `VITE_*` variable.

## Vercel configuration

Set the Vercel project root to `frontend`.

Required server-side Vercel environment variables:

| Variable | Purpose |
|---|---|
| `KAVACH_AWS_BFF_URL` | Origin of the existing AWS Node BFF; do not include a trailing path |
| `KAVACH_API_KEY` | Server-only key accepted by the AWS BFF |

Frontend build variable:

| Variable | Value |
|---|---|
| `VITE_API_BASE_URL` | Leave empty so the browser calls the same-origin Vercel `/api/*` function |

The browser never sends an API key. The Vercel function attaches the key server-side. Do not set `VITE_API_KEY`.

## AWS configuration

For the AWS CloudFront frontend build:

- Keep `VITE_API_BASE_URL` empty so the browser calls same-origin `/api/*`.
- Configure a CloudFront `/api/*` behavior whose origin is the AWS Node BFF; allow the required HTTP methods, forward query strings and request bodies, disable caching, and attach the server-side `x-api-key` origin custom header.
- Keep `API_KEY` on the AWS BFF and FastAPI runtime only. The CloudFront origin custom header must never be exposed in frontend assets.
- Store provider credentials in AWS Secrets Manager or the platform's server-side secret store.
- Configure `ENABLE_EXTERNAL_LLM_FALLBACK=true`, `OPENAI_API_KEY`, and optionally `FALLBACK_LLM_MODEL` only after approving external processing of scan metadata.

## Important availability boundary

The Vercel preview URL is a second frontend and a server-side API entry point, but it currently proxies the same AWS control plane. It therefore provides a useful second UI URL and can protect against a frontend/CDN deployment issue; **it does not provide full control-plane availability if AWS itself is down**. The CloudFront `/api/*` origin behavior must be configured separately in AWS before the AWS frontend can use the same-origin API client.

The optional model-provider fallback protects the advisory explanation step when Bedrock quota is exhausted. If the requirement expands to survive a complete AWS API/database outage, deploy a second independent runtime with its own durable state store and separately managed credentials, then add health-checked routing. Do not pretend a second frontend URL alone provides that guarantee.

## Release sequence

1. Open the PR-linked Vercel preview and validate layout, routes, theme switching, API connectivity, and error states.
2. Run frontend build and Python/backend tests in CI; verify Vercel function configuration and server-side secrets.
3. Validate the Bedrock-to-fallback provider behavior using mocked provider failures; verify the deterministic verdict is byte-for-byte unchanged.
4. Merge PR #4 only after CI and security review pass.
5. Deploy the same reviewed commit to AWS and validate the CloudFront URL, BFF, API Gateway/Lambda, Step Functions, Fargate scanner, DynamoDB, S3, and Bedrock.
6. Keep both URLs documented and monitor their health independently.
