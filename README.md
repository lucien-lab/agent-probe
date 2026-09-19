# agent-probe

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)](https://kernel.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-00599C)](https://docs.kernel.org/bpf/)
[![Status](https://img.shields.io/badge/Status-Pre--alpha-orange)](https://github.com/lucien-lab/agent-probe)

`agent-probe` is a Linux-oriented observability and policy-analysis toolkit for coding agents. It turns low-level execution evidence into an auditable record of what an agent attempted, what actually happened, how activity was attributed, and whether a declared policy was satisfied.

The project is designed around a simple rule: **unknown is not success**. Missing usage, incomplete capture, ambiguous attribution, and unsupported control paths remain visible in reports instead of being silently converted into a pass.

## Why agent-probe

Application logs are useful, but they are controlled by the application being observed. `agent-probe` provides an independent analysis path for questions such as:

- Which files were actually read or modified during a task?
- Which destinations were contacted and which model calls consumed tokens?
- What evidence connects a system event to a task, tool, or model call?
- Did a task exceed a filesystem, sensitive-data, network, or cost policy?
- Is a conclusion a fact, an inference, or insufficiently evidenced?

The architecture separates collection, immutable-style event records, correlation, policy evaluation, and enforcement analysis. This keeps a report reproducible from its source artifacts and makes uncertainty inspectable.

## Current capabilities

The repository contains a tested Python core and a minimal native BPF LSM attach probe:

| Area | Delivered capability |
| --- | --- |
| Environment discovery | `probe doctor` performs read-only checks for Linux, BTF, tracefs, tracepoints, BPF LSM, toolchain, Python/OpenSSL, and Docker prerequisites. |
| LLM accounting | Offline HTTP/1.1 framing, chunked/gzip/SSE parsing, usage-state handling, retry registration, and versioned `Decimal` pricing. |
| Event ledger | Versioned event model, append-only JSONL authority, rebuildable SQLite index, replay, sequencing, and loss accounting. |
| Attribution | Evidence graphs, external and assisted correlation modes, confidence/ambiguity propagation, and Docker task-to-host mapping abstractions. |
| Audit reports | Restricted YAML rules, deterministic findings, recomputable summaries, evidence explanation, and text/JSON/self-contained HTML output. |
| Enforcement model | Explicit audit/enforce semantics, protected-directory decisions, operation support matrix, and documented blind spots. |
| Evaluation toolkit | Classification metrics, Wilson intervals, performance summaries, and reproducible experiment-manifest validation. |
| Native validation | A small CO-RE/libbpf program verifies that an available BPF LSM hook can attach and detach cleanly without enforcing a policy. |

The collection pipeline is intentionally not overstated: there is no production TLS uprobe collector, kernel event collector, or BPF LSM policy loader yet. The native probe proves attachability only; the Python enforcement model does not block filesystem operations. See [Scope and security boundary](#scope-and-security-boundary) for the implications.

## Architecture

```text
collection sources (future)                  offline inputs (available)
TLS probes / kernel events / adapters  -->   calls artifacts + JSONL ledger
                                                    |
                                                    v
                    event validation, replay, loss accounting, SQLite index
                                                    |
                                                    v
        correlation graph <--- process / task / container / assisted markers
                                                    |
                                                    v
      YAML policy ---> deterministic audit findings ---> report / explain / HTML
                                                    |
                                                    v
                         enforcement support analysis and BPF attach validation
```

The source-of-truth format is the M2 JSONL ledger. Reports are reconstructed from the original ledger, policy, and optional calls artifact rather than from a cached aggregate.

## Quick start

Requirements: Python 3.11+ for the Python components. The native BPF probe additionally needs Linux, BTF, clang, libbpf, libelf, and kernel headers.

```bash
# Editable local install; suitable for an already-provisioned environment.
python -m pip install --no-build-isolation --no-deps -e .

# Run the test suite.
python -m pytest -q

# Inspect the host without changing it.
probe doctor
probe doctor --json
```

For development with Conda:

```bash
conda run -n ms_pointcloud_midterm python -m pip install --no-build-isolation --no-deps -e .
conda run -n ms_pointcloud_midterm python -m pytest -q
```

`probe doctor` is read-only. On macOS and Windows it returns `unsupported`, because those systems are expected to host a Linux VM rather than run the collector directly.

## Reporting and explanation

Audit reports accept a policy, an authoritative JSONL event ledger, and optionally a versioned calls artifact:

```bash
probe report \
  --policy /path/to/policy.yaml \
  --ledger /path/to/events.jsonl \
  --calls /path/to/calls.json \
  --format html \
  --output report.html

probe explain EVENT_ID \
  --policy /path/to/policy.yaml \
  --ledger /path/to/events.jsonl \
  --calls /path/to/calls.json
```

`probe report` supports `text`, `json`, and standalone `html` renderers. `probe explain` follows a finding back to the underlying raw event and records whether the result is a verified violation, a pass, or insufficient evidence.

The restricted YAML policy format supports four rule families:

- forbidden filesystem modifications;
- actual reads of sensitive paths;
- destination allow-lists for network activity; and
- estimated-cost limits.

Rules evaluate observed outcomes, not merely syscall attempts. For example, an unsuccessful write attempt does not prove a modification, and absent token usage cannot prove a cost limit was respected.

Detailed rule, report, and rendering semantics are in [docs/04-audit.md](docs/04-audit.md).

## Native BPF LSM attach probe

The attach probe is deliberately small and safe: its `file_permission` hook always returns `0`, attaches, then immediately detaches. It verifies an important environment prerequisite without installing a persistent policy.

```bash
scripts/build-lsm-attach-probe.sh
sudo bpf/lsm_attach_probe/lsm_attach_probe
```

Running the second command requires elevated privileges and loads a short-lived BPF program, so it should be performed only on an intended Linux test VM. Build and cleanup details are documented in [docs/05-bpf-lsm-attach-probe.md](docs/05-bpf-lsm-attach-probe.md).

## Repository layout

```text
src/agent_probe/
  audit/          Policy loading, evaluation, findings, reporting, rendering
  container/      Docker task/container/PID/cgroup/mount-view mapping contracts
  correlate/      Evidence graph and attribution algorithms
  enforce/        Filesystem-control model and support matrix
  events/         Event schema, ledger, index, replay, consistency checks
  evaluation/     Metrics, intervals, performance summaries, manifests
  llm/            HTTP/SSE reconstruction, usage, retries, pricing
  doctor.py       Read-only environment capability discovery
bpf/              CO-RE/libbpf BPF LSM attach probe
docs/             Design contracts, operating procedures, evaluation guidance
tests/            Deterministic unit and integration tests
scripts/          VM setup and native-probe build helpers
```

## Development and verification

The project uses a `src/` layout and pytest. Tests use deterministic byte fixtures, in-memory host abstractions, fake container queries, and temporary artifacts; they do not require Docker, a network connection, or root access.

```bash
conda run -n ms_pointcloud_midterm python -m pytest -q
conda run -n ms_pointcloud_midterm python -m agent_probe --version
conda run -n ms_pointcloud_midterm python -m agent_probe doctor --json
```

The VM setup script makes its impact explicit:

```bash
bash scripts/setup-vm.sh              # print planned changes only
bash scripts/setup-vm.sh --check-only # read-only prerequisite check
bash scripts/setup-vm.sh --apply      # explicit package/configuration changes
```

Before adding a runtime dependency, document the operational problem it solves, its maintenance cost, and the verification it enables. Python runtime dependencies are intentionally empty; native tooling remains an operating-system concern.

## Scope and security boundary

`agent-probe` currently provides offline analysis primitives, not a complete sandbox or universally deployable monitoring agent.

- The trusted computing base includes the host kernel, root, and the collector administrator. Root or kernel compromise is out of scope.
- HTTP/2, HTTP/3, static TLS, and unknown provider payloads are not supported by the current LLM reconstruction core.
- `mmap`, `io_uring`, inherited file descriptors, symlink/hard-link edge cases, and container mount views are not covered by a complete kernel enforcement implementation.
- Network and cost policy are reporting controls, not network-level blocking or billing guarantees.
- Existing metrics and experiment-manifest support are evaluation infrastructure. They are not a substitute for real-agent benchmark runs.

The most relevant design documents are:

- [Environment and doctor contract](docs/00-env.md)
- [LLM reconstruction and accounting](docs/01-llm.md)
- [Event ledger semantics](docs/02-event-ledger.md)
- [Correlation and container mapping](docs/03-correlation.md)
- [Audit policy and report model](docs/04-audit.md)
- [Enforcement model and BPF validation](docs/05-enforcement.md)
- [Evaluation protocol](docs/evaluation.md)

## Contributing

Contributions should preserve the project’s evidence model:

1. Add deterministic tests for a normal outcome, a policy violation or error path, and insufficient evidence where relevant.
2. Keep facts, inferences, and unavailable data distinct in schemas and reports.
3. Do not expose a CLI command as operational unless its underlying behavior is implemented and tested.
4. Document platform assumptions, privilege requirements, collection gaps, and cleanup behavior for native code.

Please open an issue before proposing a broad collector or policy-engine integration so that event semantics and compatibility boundaries can be agreed first.

## License

This repository does not yet include a license file. Until a license is added by the project owner, all rights are reserved and external redistribution is not granted.
