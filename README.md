# USC Office of Cybersecurity — DFIR Evidence Collection

Authorized enterprise security application for one-time evidence collection through CrowdStrike Falcon RTR or SentinelOne Remote Script Library, Asset Coverage across CrowdStrike/SentinelOne/Tenable, and Tenable Vulnerability Management.

## Authentication and authorization

The application presents its own username/password front page for application-level RBAC. Production deployments also require Cloudflare Access verification at the origin. The application validates the Cloudflare Access JWT when configured and records the authenticated Cloudflare identity for auditing.

Workspace permissions are enforced server-side:

- `dfir` — DFIR Evidence Collection
- `assets` — Asset Coverage
- `vuln` — Vulnerability Management

Only administrators can access Settings and manage application users and permissions.

## DFIR Evidence Collection

The collector uses server-managed Velociraptor offline collectors. Collection profiles are predefined; the browser cannot supply arbitrary commands. CrowdStrike uses Falcon RTR and SentinelOne uses approved Remote Script Library execution with Fetch Files retrieval.

Jobs run through persistent background workers and survive application restarts. Evidence is integrity-verified, encrypted at rest, retained according to policy, and streamed as a decrypted download without creating an unnecessary plaintext copy.

## SentinelOne transport password

Each GUI collection push generates one cryptographically random 32-character Fetch Files password shared by every endpoint in that push. It is encrypted in the database, returned only in the push response, and never exposed through normal job listings or audit logs.

## CrowdStrike transport

CrowdStrike RTR transport archives use the configured server-side transport password and are normalized into the standard Velociraptor evidence archive before verification.

## Asset Coverage

Asset Coverage retrieves inventories server-side from CrowdStrike, SentinelOne, and Tenable, deduplicates them using normalized hostnames/FQDNs, IP addresses, and MAC addresses, and provides filters for missing coverage plus CSV export. Inventory synchronization runs at 00:00, 06:00, 12:00, and 18:00 in the server/container local timezone.

## Vulnerability Management

Tenable Vulnerability Management is the source for vulnerability findings. The application provides Executive, Findings, Microsoft Patch Cadence, and Linux FP Review views. Linux findings are automatically enriched only where authoritative vendor security data is available.

## Configuration

Copy `.env.example` to `.env`, generate secrets with `scripts/generate_secrets.py`, configure the EDR/Tenable/Velociraptor settings, and start the stack with Docker Compose.


## Cloudflare Access

Configure `CLOUDFLARE_ACCESS_TEAM_DOMAIN` and `CLOUDFLARE_ACCESS_AUDIENCE`. The origin fails closed if the required Access configuration is absent. The application does not treat a missing Cloudflare boundary as an acceptable production state.
