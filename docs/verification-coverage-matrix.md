# cis-docker — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.**

This profile is **dual-mode** (`docker_target_mode`). The trust boundary differs
by mode, so the disposition is given per mode.

## container_only mode (SPARC — Fargate; the runtime target)

| Disposition | Count | Notes |
|---|---|---|
| `implemented` | 15 | Direct assertions feasible from inside the container |
| `inherited` → `:leveraged` | 63 | dockerd/host/runtime are AWS-managed; AWS authorization freshness-checked (#165) |
| `alternative` → `:boundary` attest | 31 | image-provenance / per-workload policy not visible from inside the container; documented in #165 |
| not-applicable | 9 | host-only concerns N/A in container_only |

In SPARC's mode the trust boundary is already fully dispositioned: nothing is
*trusted* — it is either asserted, `:leveraged`-evidenced, or attested with a
freshness floor.

## host_daemon mode (non-Fargate consumers running their own dockerd)

The 31 controls that are `alternative` here are **verifiable** — they are the CIS
Docker host/daemon benchmark items, each checkable against a docker host:

| CIS section | Verification mechanism | Status |
|---|---|---|
| §1 host config (1.1.x, 1.2.x) | `file`/`directory` perms+ownership on `/etc/docker`, `docker.service`, `docker.sock`; `auditd` rules; package state | verifiable — **gated on #172** |
| §2 daemon config (2.x) | `docker` daemon config flags (`icc`, `userns-remap`, `live-restore`, `no-new-privileges`, logging driver, TLS) via `/etc/docker/daemon.json` / `docker info` | verifiable — **gated on #172** |
| §3 daemon files (3.x) | `file` perms+ownership on daemon/registry/TLS files | verifiable — **gated on #172** |

### Why not built yet (integrity)
These require a **docker host target** to exec against — the same constraint as
cis-nginx. Implementing 31 host checks *before* the build-time docker-exec path
exists (**sparc-validate#172** — add `train-docker` + docker CLI to the scanner
image, then `-t docker://`) would ship logic that **cannot be validated**,
contrary to the verify-don't-trust principle (we'd be trusting our own unverified
checks). They are therefore specified here and **blocked on #172**; once a docker
target is execable, they become `implemented` and are exec-validated.

SPARC itself runs `container_only`, so this host_daemon surface is for non-SPARC
consumers; it carries no SPARC-runtime risk in the interim.
