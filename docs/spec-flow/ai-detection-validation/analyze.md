# A09 AI-Assisted Detection Validation — Consistency Analysis

## Recommendation

**GO.** The requirements, architecture, and tasks agree on the user, scope, vendor, safety boundary, data flow, status
model, and test strategy. Every functional requirement is covered by at least one implementation task.

## Coverage check

| Requirement area | Planned coverage |
| --- | --- |
| Opt-in A09 scope and staging validation | T1, T7 |
| Public/YAML contracts and secret references | T1, T2 |
| Frozen matched corpus and stable markers | T3 |
| Calibration, emission, Splunk polling, scoring | T4 |
| Retry/resume and workflow completion | T5 |
| Canonical evidence, report, and A09 coverage | T6 |
| Configuration and Run Detail UI | T7 |
| Full verification and operator documentation | T8 |

## Consistency findings

- Terminology is stable: `alerting-effectiveness` is the selectable scope, `detection-validation` is its executor/phase,
  and `detection_validation` is the persisted result/config spelling.
- The status model is intentionally separate from Temporal workflow status. `failed` means a valid scored defensive
  miss, while `partial` and `unavailable` mean the assessment did not produce a complete score.
- The ten simulations are fixed data, not exploit logic or runtime model output. Their only destination is a dedicated
  staging no-op endpoint.
- The architecture reuses existing scope, protected-config, atomic-evidence, deterministic-report, profile, and Run
  Detail paths; no new datastore, dependency, or vendor interface is justified.

## Risks to verify during implementation

1. CLI and worker scope/config registries are duplicated. Contract tests must assert identical IDs, defaults, and
   validation behavior.
2. Protected pipeline config currently carries target secrets. The Splunk token must be stripped from run snapshots,
   resume hashes, logs, errors, reports, and API responses while remaining available to the worker activity.
3. Report coverage must count both `passed` and threshold-based `failed` as assessed; otherwise a defensive miss would
   be mislabeled as missing coverage.
4. Splunk export responses are streamed. Parsing must be bounded, tolerate message records, and never persist `_raw`.
5. A retry must not create new markers or double-count alerts. Completed evidence should short-circuit re-emission.
6. The existing workflow can select executor-only scopes. Tests must prove report generation still works with zero
   vulnerability-agent lanes.

No contradictions or uncovered requirements block implementation.
