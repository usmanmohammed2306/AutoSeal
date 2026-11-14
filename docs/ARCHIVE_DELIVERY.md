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

The validator also compares the API runtime files and Studio build-source snapshot against the current checkout. Rebuild after changing either application. An older image that starts successfully still fails this source check; startup alone cannot validate the current implementation.

## Review the public TLS configuration

`deploy/Caddyfile` is the future public configuration. It redirects HTTP to HTTPS and selects the ACME `shortlived` profile. Its offline syntax check passed for a reserved documentation IP. Public issuance and renewal have not been demonstrated.

Let's Encrypt documents 160-hour IP certificates, which offers a possible route without buying a domain. The public server still needs reachable challenge ports, persistent protected certificate storage, actual renewal checks and an approved configuration. [CA announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/), [Caddy issuer configuration](https://caddyserver.com/docs/caddyfile/directives/tls).

The supplied Compose files expose only loopback listeners. They do not provision AWS, expose a public application, upgrade a Free plan or enable live agent execution. Public delivery needs its own reviewed cost and operational evidence. Use [architecture](ARCHITECTURE.md) and [release inspection](RELEASE_CHECK.md) to keep those requirements visible.


## Rehearse backup, restore and application rollback

The optional recovery check imports one freshly evaluated, reviewed Pytest fixture through a trusted local management process. The public API stays read-only. Candidate execution remains Mac Docker. It then backs up PostgreSQL in custom format and the content-addressed evidence files, verifies the snapshot, and restores into another Compose project with fresh volumes. Run records, evidence bytes and event history must match through the restored reader API. A deliberately corrupted copy must fail before database restoration.

```bash
python scripts/validate_archive_delivery.py --https --recovery \
  --root .autoseal/archive-recovery-check-001
```

For an actual application-version rollback rehearsal, retain a separately built, reviewed earlier API image locally. Pass its immutable image identity with `--rollback-image sha256:YOUR_LOCAL_REVIEWED_IMAGE_DIGEST`. The validator serves the restored evidence with that previous image, returns to the current image and verifies both identities and responses. It refuses the current image as its own rollback target and never downloads an arbitrary rollback image.

The snapshot manifest binds each file's name, length and digest, including the database dump. Verification requires the original manifest identity retained by the validator. Only the database dump and correctly addressed CAS objects may enter the snapshot; traversal, symlinks, altered payloads and oversized inventories are refused. Backups use private filesystem permissions and remain local. They are not a credential backup or an arbitrary tar-extraction interface.

PostgreSQL readiness uses TCP to avoid the temporary socket-only initialization server. Earlier validation attempts retained both a missing-reader-credential error in the test harness and this initialization race before correction. The final local rehearsal passed 28 checks, including TLS, independent-volume restoration, a corrupt-copy refusal, previous/current API image switching and cleanup of both stacks.

This checks one quiescent local fixture archive and two compatible application images. It does not establish AWS recovery, active-writer snapshot consistency, arbitrary schema rollback, production RPO/RTO, a reviewed model-evidence upload or a live execution bridge. Scheduled off-host retention and an operated restore still belong to the deployment acceptance.

## Prepare protected model evidence

`scripts/prepare_archive_payload.py` checks the original SFT and hidden-audit evaluations, copies only their reachable content objects into a new private directory, then verifies the exported graphs again. It never copies a whole research directory or uploads anything. Use `--help` for the required archive paths and evaluation identities. Missing source evidence, changed bytes, oversized graphs and credential-shaped byte patterns cause refusal. The byte-pattern check is limited and still requires an actual private evidence review.

The reference payload contains 7,634 content objects and 333,552,678 bytes. It includes inert adapter/optimizer evidence needed to verify training lineage. The 7B base weights are represented by their provenance inventory, not copied. Original machine paths can remain in protected receipts. Keep this payload outside Git and mount it read-only; no model-weight download endpoint is added.

For an authorized local test, `validate_archive_delivery.py` accepts `--model-payload` together with `--payload-id`, the manifest's original SHA-256 identity. The API independently verifies both model views inside the container. The validator also reads the actual Studio response stream and checks that its checking state arrives before the completed model table, with application credentials absent from the response.

The training page streams its panels independently. In one local x86-emulated, CPU-limited test, checking-state bytes arrived after 0.041 seconds and the completed stream after 26.60 seconds. Full receipt checking still took about 26 seconds. This is a single HTTP stream observation, not browser first paint, a percentile, a speedup in verification or cloud latency. Missing and failed archives keep their explicit unavailable states.

## Review a future public deployment

`deploy/compose.public-review.yaml` is a configuration to review before deployment approval. It pins the target platform to Linux/amd64, requires reviewed immutable application image identities, bounds container logs and exposes only the TLS proxy publicly on 80/443. API and PostgreSQL remain private, Studio stays authenticated and reader-only, and no worker is added. Its explicit `public-review` profile must be selected before the proxy can start.

`deploy/compose.model-evidence.yaml` optionally mounts the reviewed payload at `/srv/model-evidence` with read-only access and requires the two original evaluation identities. These files neither provision AWS nor upgrade a plan. Public execution still requires the approved configuration, actual HTTPS, private credentials and separate deployment/cost authorization.

For local target-image compatibility, build the trusted images with `docker build --platform linux/amd64 ...`. Record their `docker image inspect` identities in a JSON inventory with exactly `platform`, `api`, `studio` and `proxy` keys. Supply it to `validate_archive_delivery.py --https --image-inventory ...`. The validator refuses another declared platform, mutable image references or locally absent/wrong-architecture images. Linux/amd64 recovery passed 28 checks under Mac emulation. A separate protected-payload and streaming check passed 22. Neither is a deployed AWS service or native cloud performance result.
