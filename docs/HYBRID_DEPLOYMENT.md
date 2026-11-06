# Kavach frontend-first rebuild

## Current phase: frontend product experience

The first milestone is a complete, independently navigable Runtime Security Simulator. The frontend must remain usable when AWS, API Gateway, the Node BFF, FastAPI, Bedrock, or any other backend service is unavailable.

The React application currently uses deterministic local demo fixtures and local state. It does not make backend requests. This is intentional for the UI-first phase.

## Frontend pages

- **Home:** Runtime Security Simulator landing page, quick scenarios, demo system-health indicators, recent runs, and session metrics.
- **Simulator:** workflow composer, scenario selection, local execution stages, and simulated authorization result.
- **Scenarios:** four guided exercises covering unauthorized data access, malicious code execution, compromised agents, and supply-chain risk.
- **Shield:** protection posture, demo authorization decisions, and per-request trace inspection.
- **Artifact Scanner:** local file selection, illustrative scan stages, demo verdict, and explicit disclosure that the result is not a malware verdict.
- **Agents:** agent registry, trust/capability display, and local quarantine/restore interactions.
- **Policies (Cedar):** policy library, details, and local enable/disable toggles.
- **Audit & Traces:** filterable event history, trace detail modal, simulation history, and JSON export.

## Simulator data boundary

All fixtures and generated decisions are demo-only:

- The UI labels itself **SIMULATOR** and **DEMO DATA**.
- Local allow/deny results do not represent real Cedar decisions.
- Local quarantine/restore changes do not modify an actual agent identity.
- The artifact scanner uses a filename-based illustrative heuristic; it does not inspect file bytes or certify an artifact as safe.
- No selected file is uploaded to a server.
- The Production selector is intentionally disabled until backend integration is approved.
- The UI does not show a backend-offline error because it does not depend on the backend in this phase.

These constraints must remain visible in the UI until real backend responses are connected.

## Deployment

- **Vercel preview:** first build, review, and interaction-testing target.
- **AWS CloudFront:** existing production URL remains unchanged during the frontend rebuild.

Vercel and AWS are separate frontend deployment targets. The frontend currently runs in simulator mode on both until the backend integration phase is explicitly started.

## Backend integration phase (deferred)

After the frontend is reviewed and approved:

1. Connect the frontend API client to the AWS Node BFF and FastAPI control plane.
2. Replace demo fixtures incrementally with typed API responses.
3. Add loading, empty, stale-data, permission-denied, rate-limit, and service-unavailable states.
4. Connect workflow execution, scanner jobs, Shield events, agent actions, Cedar policy reads, and audit traces.
5. Keep production actions fail-closed; never substitute a local demo result for an unavailable authorization service.
6. Add contract tests and end-to-end tests before enabling the Production selector.

The existing backend architecture remains the target integration contract. This phase deliberately does not attempt to fix or redeploy backend services.

## Review checklist

- [ ] Vercel preview loads without backend environment variables.
- [ ] All eight navigation destinations render.
- [ ] Scenario modal and simulation flow work.
- [ ] Agent quarantine and restore update only local demo state.
- [ ] Policy toggles are clearly labelled as local.
- [ ] Artifact scanner accepts a local file and clearly labels its heuristic result.
- [ ] Event detail modal opens from Shield and Audit.
- [ ] Audit filters and JSON export work.
- [ ] Theme toggle and responsive layouts work.
- [ ] No UI claims that simulated state is production security telemetry.
