# cis-docker-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-docker-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-docker-baseline)

InSpec / CINC Auditor profile validating a **Docker host and daemon** against the
**CIS Docker Benchmark v1.8.0** — 118 controls across host configuration, daemon
configuration, daemon files and directories, container images, and container
runtime.

---

## This is a daemon and host benchmark, not an image scanner

The single most important thing to know before running it. The profile assesses:

- the Docker **daemon's** configuration
- the **host files** backing it — `/etc/docker/daemon.json`, systemd units,
  socket ownership and permissions
- the **containers that daemon is running**

**Pointing it at an application container does not work.** A container is not a
Docker host: the host-file controls fail for reasons that have nothing to do with
your security posture, and short-lived containers exit before they can be
inspected. This was tried and reverted.

It has to run where the daemon runs:

```bash
# on the Docker host
cinc-auditor exec . -t local:// --input-file inputs/mine.yml

# or remotely
cinc-auditor exec . -t ssh://user@docker-host --input-file inputs/mine.yml
```

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-docker-baseline
cd cis-docker-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t local:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

Needs root, or an account that can read the daemon configuration, the socket and
the systemd units, and query the daemon.

### What a first run looks like

**118 controls, 171 results, zero control source-code errors.**

The pass/fail split depends entirely on the host. The measurement above came from
a run **inside a container with the daemon socket mounted** — enough to prove the
profile executes correctly end to end, but *not* a Docker host, so the host-file
and daemon-configuration controls failed for environmental reasons rather than
real findings.

Take **171 results and zero errors** as the shape of a working run. A real Docker
host will produce the same result count with a meaningful split. Far fewer
results means the profile is not reaching the daemon.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `docker_target_mode`, `docker_socket_paths` |
| **Policy** | `docker_authorized_registries`, `docker_image_user_allowlist` |
| **Logging** | `logging_strategy`, `logging_requirements`, `logging_attestation_reference` |
| **Attestation** | the `*_base` URIs, `inherited_evidence_uri`, two staleness windows |

**`docker_authorized_registries` empty is not "every registry is trusted".** It
means the control has nothing to check against and reports that.

**The attestation bases matter more here than they look.** On a managed runtime,
or a host hardened by another team, the daemon configuration is somebody else's
responsibility — those controls want evidence of that, not a pass.

---

## Controls

118 controls following the CIS Docker v1.8.0 sections:

| Section | Assesses |
|---|---|
| 1 | host configuration — partitioning, kernel, auditd rules for the Docker paths |
| 2 | daemon configuration — TLS, logging level, live restore, userns, default ulimits |
| 3 | daemon files and directories — ownership and permissions on the socket, config and units |
| 4 | container images — non-root user, trusted base, health checks, no secrets in layers |
| 5 | container runtime — capabilities, privileged mode, mounts, network mode, restart policy |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-docker-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-docker-host
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-docker-v1.8.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
      target_uri: 'local://'
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-docker-baseline
    ref: v0.1.7
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-docker-host
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-docker-v1.8.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
```

`target`, `boundary`, `aws_region`, `profile_name` and `profile_version` are
required and have no defaults. A missing one is rejected before the job starts —
GitHub refuses the `workflow_call`, GitLab refuses the `include` — rather than
running against the wrong account or filing the results under the wrong label.
`inputs_file` defaults to `inputs/example.yml`, which runs with example values,
so set it to your own copy. See [docs/ci-templates.md](docs/ci-templates.md) for
the full contract, including which secrets are genuinely optional.

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: the shared evidence-store schema.

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-docker-v1.8.0
    git: https://github.com/risk-sentinel/cis-docker-baseline.git
    tag: v0.1.4
```

Then `include_controls 'cis-docker-v1.8.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
