# Run the trusted application containers

This profile serves saved evidence through authenticated Studio and API containers. Its execution boundary refuses mutations and the older research GET routes that can run experiments. The application container contains no Docker client/socket, worker, cluster credential or private planning folder.

PostgreSQL, Alembic migrations and reader authentication run for real. The supplied validator checks an empty database and removes its own containers, volumes and network afterward. Importing a reviewed evidence corpus, backup/restore, public certificate operation and AWS deployment remain separate delivery requirements.

## Build locally

From the repository root, using Mac Docker:

```bash
docker build --pull=false -f deploy/api.Dockerfile \
  -t autoseal-api:archive-local .
docker build --pull=false -f deploy/studio.Dockerfile \
  -t autoseal-studio:archive-local apps/studio
docker build --pull=false --network=none -f deploy/caddy.Dockerfile \
  -t autoseal-proxy:archive-local .
```

The Dockerfiles pin official base-image digests. Python server dependencies have explicit versions, and Studio uses its frozen pnpm lockfile. The first build downloads those trusted dependencies. The API build context has a whitelist; private archives and configuration are excluded.

The proxy derives from Caddy 2.11.7. Its official binary carries a low-port capability. This profile removes that capability, uses high container ports and runs as a nonroot user with every capability dropped. Candidate execution profiles are separate.

## Validate the complete local profile

After installing the development/server dependencies from the root README:

```bash
python scripts/validate_archive_delivery.py --https \
  --root .autoseal/archive-delivery-check-001
```

Use a new output directory for each attempt. The script creates disposable credentials in memory and a uniquely named Compose project. It checks migrations, authentication, empty saved runs, disabled execution even with the operator credential, excluded private files, restricted containers and scoped cleanup.

The HTTPS extension creates an isolated private CA inside its own proxy volume. The test client verifies that chain and the loopback IP using only that CA file. It does not install a certificate authority into your Mac's trust store, request a public certificate or contact AWS. Failures remain in the output directory. Check `status`, every individual check and `cleanup_succeeded` in `report.json`.

The API becomes healthy only after an authenticated saved-run query reaches PostgreSQL. Studio waits for that state, and its own health check requires unauthenticated access to be denied. The TLS proxy waits for Studio. The first validation attempt exposed the need to wait for API startup; that failed attempt remains in the local evidence record.

## Review the public TLS configuration

`deploy/Caddyfile` is the future public configuration. It redirects HTTP to HTTPS and selects the ACME `shortlived` profile. Its offline syntax check passed for a reserved documentation IP. Public issuance and renewal have not been demonstrated.

Let's Encrypt documents 160-hour IP certificates, which offers a possible route without buying a domain. The public server still needs reachable challenge ports, persistent protected certificate storage, actual renewal checks and an approved configuration. [CA announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/), [Caddy issuer configuration](https://caddyserver.com/docs/caddyfile/directives/tls).

The supplied Compose files expose only loopback listeners. They do not provision AWS, expose a public application, upgrade a Free plan or enable live agent execution. Public delivery needs its own reviewed cost and operational evidence. Use [architecture](ARCHITECTURE.md) and [release inspection](RELEASE_CHECK.md) to keep those requirements visible.
