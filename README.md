# Docker CIS Baseline

InSpec / CINC Auditor profile validating a Docker / OCI container deployment against **CIS Docker Benchmark v1.8.0**.

## Scope

The profile is designed to run unchanged across two consumer topologies, selected via the `docker_target_mode` input:

- **`host_daemon`** — full-fat Docker host (the consumer operates `dockerd` themselves on EC2 / on-prem). All 118 controls are in scope; checks read host filesystem, inspect daemon config, and query `docker` CLI / API where applicable.
- **`container_only`** — opaque container runtime (the consumer runs workloads via a managed service like AWS Fargate that hides the daemon and host). Sections that the consumer literally cannot satisfy are reclassified accordingly:
  - **§1 + §2 + §3 → `inherited`** (AWS satisfies under the shared-responsibility model — SOC 2 Type II / FedRAMP M+H / ISO 27001).
  - **§7 → `not-applicable`** (Docker Swarm is not running at all; ECS scheduling is the substitute, so there is no AWS-operated layer satisfying these — the architectural reality is genuine non-applicability).

§4 (image), §5 (runtime), §6 (operations) stay live in both modes — image content and runtime config are the consumer's responsibility regardless of where the workload runs.

Consumers running their workloads on managed container services (e.g., AWS Fargate, Azure Container Apps) set `docker_target_mode: container_only`. Consumers operating their own Docker host stay on the default `host_daemon` mode.

## Running Locally

Prerequisites: Docker. No vendor step required (no external `depends:`).

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1
```

### container_only mode — running container target

```bash
docker run --rm \
  -v "$PWD:/src" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-docker \
  -t docker://<container-id-or-name> \
  --input-file /src/profiles/cis-docker/inputs.yml \
  --reporter cli json:/src/hdf.json
```

### Host-daemon mode — full Docker host

```bash
docker run --rm \
  -v "$PWD:/src" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/docker:/etc/docker:ro \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-docker \
  --input docker_target_mode=host_daemon \
  --reporter cli json:/src/hdf.json
```

## Portability

Four inputs cover the container-runtime classification surface.

| Input | Default | When to override |
|---|---|---|
| `docker_target_mode` | `host_daemon` | Set to `container_only` when running against a managed container runtime that hides the daemon (Fargate, EKS Pod Identity, etc.). Drives the implementation_status classification on §1 / §2 / §3 / §7. |
| `docker_image_user_allowlist` | `[]` | Optional allowlist of acceptable container USER values (uid or username). Empty falls back to "must not be root" only; non-empty enforces strict membership. |
| `docker_authorized_registries` | `[]` | Optional registry-prefix allowlist for image pull sources (CIS 4.2). Pairs with `trusted_image_registries` on cis-aws-compute. Empty falls back to attestation. |
| `docker_socket_paths` | `[/var/run/docker.sock, /run/docker.sock]` | Candidate docker-socket paths for CIS 5.32 (no socket bind-mount inside container). Override only for non-default socket locations. |

### Example: container_only consumer `inputs.yml` (Fargate / managed runtime)

```yaml
docker_target_mode: container_only
```

### Example: host-Docker consumer with strict policy

```yaml
docker_target_mode: host_daemon
docker_image_user_allowlist:
  - nginx
  - app
  - '1000'
docker_authorized_registries:
  - 752531709667.dkr.ecr.us-east-1.amazonaws.com/
  - public.ecr.aws/myorg/
```

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from the XCCDF's DISA CCI identifiers via Heimdall's `CciNistMappingData.ts`.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/cis_docker_benchmark_v18.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-docker \
  --profile-name cis-docker \
  --profile-title "Docker CIS Baseline" \
  --supports-platform container --partitions "" --no-inspec-aws
```

## Status

All 118 controls filled (issue #16). Each control carries a `tag implementation_status:` mapped to OSCAL's native vocabulary — see the [Control Classification Guide](../../docs/dev/Control_Classification_Guide.md) for the 5-bucket taxonomy. The dual-mode classification (host_daemon vs container_only) is implemented via runtime conditionals in the control body (`if input('docker_target_mode') == 'container_only'`) — both the `tag` and the `describe` branches are mode-aware.

### Coverage distribution — `container_only` mode

| Type | `implementation_status` | Count | Sections |
|---|---|---|---|
| **Inherited** | `inherited` | 63 | §1 + §2 + §3 |
| **Automated** | `implemented` | 14 | §4 (2) + §5 (12) |
| **Attestation** | `alternative` | 32 | §4 (10) + §5 (20) + §6 (2) |
| **Not applicable** | `not-applicable` | 9 | §7 |

Each `inherited` control carries the standard inheritance-attestation tags (`inherited_from: aws-shared-responsibility` + `attestation_references` for AWS SOC 2 Type II / FedRAMP M+H / ISO 27001).

### Coverage distribution — `host_daemon` mode

| Type | `implementation_status` | Count |
|---|---|---|
| **Automated** | `implemented` | 65 |
| **Attestation** | `alternative` | 53 |

§1 + §2 + §3 host_daemon checks use `file`, `auditd`, `mount`, `processes`, and `json` (for `/etc/docker/daemon.json`) built-ins. §7 host_daemon checks use `command('docker ...')` against the local daemon.

### Per-section breakdown (container_only mode)

| Section | Subject | Controls | Implemented | Alternative | Inherited | Not-applicable |
|---|---|---|---|---|---|---|
| 1 | Host configuration | 20 | 0 | 0 | 20 | 0 |
| 2 | Daemon configuration | 19 | 0 | 0 | 19 | 0 |
| 3 | Daemon configuration files | 24 | 0 | 0 | 24 | 0 |
| 4 | Images / Dockerfile | 12 | 2 | 10 | 0 | 0 |
| 5 | Container runtime | 32 | 12 | 20 | 0 | 0 |
| 6 | Security operations | 2 | 0 | 2 | 0 | 0 |
| 7 | Docker Swarm | 9 | 0 | 0 | 0 | 9 |

### Cross-reference with cis-aws-compute

Several §5 attestations cross-reference cis-aws-compute §3 — where the task-definition surface already enforces the same intent that running-container introspection can't observe from inside Fargate:

- **5.5** (privileged) — automated via `/proc/self/status` CapEff, but task-definition side is cis-aws-compute 3.4.
- **5.10** (host network namespace) — task-definition: cis-aws-compute 3.1 (network mode != host with privileged).
- **5.16** (host PID namespace) — task-definition: cis-aws-compute 3.3 (pidMode != host).
- **5.27** (HEALTHCHECK runtime) — image side: §4.6; task-definition side: ECS healthCheck field.

### `exec_validated` semantics

Every control carries `tag exec_validated: false`. cinc-auditor `check` passes on all 118 with both modes; live exec hasn't run yet. The first container-target exec post-merge will exercise the 14 automated `container_only` controls. Host-daemon validation depends on having a Docker host to scan.

## See also

Top-level `README.md` for overall repo state and the sub-issue tracker for per-profile progress.
