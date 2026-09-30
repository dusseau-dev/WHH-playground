import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CircleDollarSign,
  Clock3,
  Download,
  ExternalLink,
  FileDown,
  FileWarning,
  KeyRound,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Square,
  TerminalSquare,
  Users,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import { useParams } from "react-router-dom";
import rehypeSanitize from "rehype-sanitize";
import remarkGfm from "remark-gfm";
import { Button, ErrorState, InlineNotice, LoadingRows, PageHeader } from "../components/Primitives";
import { ModeBadge, ProgressMeter, StageIcon, StatusBadge } from "../components/RunStatus";
import { ApiError, api, subscribeToRun } from "../lib/api";
import {
  formatCost,
  formatDuration,
  formatTimestamp,
  safeMarkdownUrl,
  sortFindings,
} from "../lib/presentation";
import { isElevatedHttpLoad } from "../types/api";
import type {
  ActivityEntry,
  Finding,
  PipelineStage,
  ReportArtifact,
  RunDetail,
  Severity,
  TargetSecretField,
  TargetSecrets,
} from "../types/api";

type TabId = "findings" | "report" | "activity";
type StreamState = "connecting" | "connected" | "reconnecting" | "closed";

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const terminalStatuses = new Set(["completed", "failed", "cancelled"]);
const secretLabels: Record<TargetSecretField, string> = {
  password: "Target password",
  totpSecret: "Target TOTP secret",
  emailPassword: "Email account password",
  emailTotpSecret: "Email account TOTP secret",
};

function mergeActivity(current: ActivityEntry[], incoming: ActivityEntry[]): ActivityEntry[] {
  const byId = new Map(current.map((entry) => [entry.id, entry]));
  for (const entry of incoming) byId.set(entry.id, entry);
  return [...byId.values()].sort((left, right) => left.timestamp.localeCompare(right.timestamp)).slice(-1_000);
}

function RunMetrics({ run }: { run: RunDetail }) {
  const metrics = [
    { label: "Elapsed", value: formatDuration(run.metrics?.elapsedMs), icon: Clock3 },
    { label: "Cost", value: formatCost(run.metrics?.costUsd), icon: CircleDollarSign },
    { label: "Selected checks", value: String(run.scope.testScopes.length), icon: RefreshCw },
    { label: "Findings", value: String(run.metrics?.findings ?? run.findings.length), icon: ShieldAlert },
    {
      label: "Active tests",
      value: String(run.progress.activeTestCategories.length + run.progress.activeModules.length),
      icon: Users,
    },
  ];

  return (
    <section className="metric-band" aria-label="Run metrics">
      {metrics.map(({ label, value, icon: Icon }) => (
        <div className="metric-cell" key={label}>
          <Icon size={16} aria-hidden="true" />
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </section>
  );
}

function PipelineTimeline({ stages }: { stages: PipelineStage[] }) {
  const lanes = useMemo(() => {
    const grouped = new Map<string, PipelineStage[]>();
    for (const stage of stages) {
      const lane = grouped.get(stage.lane) ?? [];
      lane.push(stage);
      grouped.set(stage.lane, lane);
    }
    return [...grouped.entries()];
  }, [stages]);

  if (!stages.length) {
    return <div className="timeline-empty">Pipeline is waiting for its execution plan.</div>;
  }

  return (
    <section className="pipeline-section" aria-labelledby="pipeline-heading">
      <div className="section-title-row">
        <h2 id="pipeline-heading">Pipeline execution status</h2>
        <span>{lanes.length} concurrent lanes</span>
      </div>
      <div className="pipeline-timeline">
        {lanes.map(([lane, laneStages]) => (
          <div className="timeline-lane" key={lane}>
            <div className="lane-label">{lane}</div>
            <div className="lane-track">
              {laneStages.map((stage) => (
                <div className={`timeline-stage timeline-stage--${stage.status}`} key={stage.id}>
                  <StageIcon status={stage.status} />
                  <span className="stage-copy">
                    <strong>{stage.label}</strong>
                    <small>{stage.detail ?? formatDuration(stage.durationMs)}</small>
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function FindingRow({ finding, runId }: { finding: Finding; runId: string }) {
  return (
    <article className="finding-row">
      <div className="finding-heading">
        <span className={`severity severity--${finding.severity}`}>{severityLabels[finding.severity]}</span>
        <div>
          <h3>{finding.title}</h3>
          <div className="finding-meta">
            <span>{finding.vulnType}</span>
            <span>{finding.verdict.replaceAll("-", " ")}</span>
          </div>
        </div>
      </div>
      {finding.description || finding.reason ? <p>{finding.description ?? finding.reason}</p> : null}
      {finding.evidence?.length ? (
        <div className="evidence-list" aria-label="Evidence">
          {finding.evidence.map((artifact) => (
            <a href={api.artifactUrl(runId, artifact.id)} key={artifact.id} download>
              <FileDown size={15} aria-hidden="true" />
              <span>{artifact.name}</span>
              {artifact.sizeBytes ? <small>{Math.ceil(artifact.sizeBytes / 1024)} KB</small> : null}
            </a>
          ))}
        </div>
      ) : null}
    </article>
  );
}

function FindingsPanel({ findings, runId }: { findings: Finding[]; runId: string }) {
  const actionable = sortFindings(findings.filter((finding) => finding.verdict !== "ruled-out"));
  const ruledOut = sortFindings(findings.filter((finding) => finding.verdict === "ruled-out"));

  return (
    <div className="findings-panel">
      <div className="finding-counts" aria-label="Finding totals">
        <strong>{actionable.length} actionable</strong>
        <span>{ruledOut.length} ruled out</span>
      </div>
      {actionable.length ? (
        <div className="finding-list">
          {actionable.map((finding) => (
            <FindingRow key={finding.id} finding={finding} runId={runId} />
          ))}
        </div>
      ) : (
        <div className="tab-empty">
          <ShieldAlert size={21} aria-hidden="true" />
          <span>No actionable findings are available.</span>
        </div>
      )}
      {ruledOut.length ? (
        <details className="ruled-out-group">
          <summary>{ruledOut.length} ruled-out findings</summary>
          <div className="finding-list finding-list--ruled-out">
            {ruledOut.map((finding) => (
              <FindingRow key={finding.id} finding={finding} runId={runId} />
            ))}
          </div>
        </details>
      ) : null}
    </div>
  );
}

function ReportPanel({ runId, artifacts }: { runId: string; artifacts: ReportArtifact[] }) {
  const markdownAvailable = artifacts.some((artifact) => artifact.kind === "markdown");
  const reportQuery = useQuery({
    queryKey: ["runs", runId, "report"],
    queryFn: () => api.getReport(runId),
    enabled: markdownAvailable,
  });

  if (markdownAvailable && reportQuery.isLoading) return <LoadingRows count={8} />;
  if (reportQuery.isError) {
    return (
      <ErrorState
        message={reportQuery.error instanceof Error ? reportQuery.error.message : "Report could not be loaded"}
        retry={() => void reportQuery.refetch()}
      />
    );
  }
  if (!reportQuery.data && artifacts.length === 0) {
    return (
      <div className="tab-empty">
        <FileWarning size={21} aria-hidden="true" />
        <span>The report is not available yet.</span>
      </div>
    );
  }

  return (
    <div className="report-panel">
      <div className="report-toolbar">
        <span>Rendered report</span>
        <div className="report-downloads">
          {artifacts.map((artifact) => (
            <a
              className="button button--secondary"
              href={api.reportArtifactDownloadUrl(runId, artifact.kind)}
              download={artifact.filename}
              key={artifact.kind}
            >
              <Download size={16} aria-hidden="true" />
              <span>Download {artifact.kind === "pdf" ? "PDF" : artifact.kind === "sarif" ? "SARIF" : "Markdown"}</span>
            </a>
          ))}
        </div>
      </div>
      {reportQuery.data ? <article className="markdown-report">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeSanitize]}
          skipHtml
          urlTransform={safeMarkdownUrl}
          components={{
            img: () => null,
            a: ({ href, children }) => (
              <a href={href} target="_blank" rel="noreferrer">
                {children}
                <ExternalLink size={13} aria-hidden="true" />
              </a>
            ),
          }}
        >
          {reportQuery.data}
        </ReactMarkdown>
      </article> : (
        <div className="tab-empty">
          <FileWarning size={21} aria-hidden="true" />
          <span>A Markdown preview is unavailable. Download an available report artifact above.</span>
        </div>
      )}
    </div>
  );
}

function ActivityPanel({
  entries,
  streamState,
  onReconnect,
}: {
  entries: ActivityEntry[];
  streamState: StreamState;
  onReconnect: () => void;
}) {
  const [follow, setFollow] = useState(true);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (follow) listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
  }, [entries, follow]);

  return (
    <div className="activity-panel">
      <div className="activity-toolbar">
        <span className={`stream-state stream-state--${streamState}`}>{streamState}</span>
        <div className="button-group">
          <Button
            variant="ghost"
            icon={follow ? <Pause size={16} aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
            onClick={() => setFollow((value) => !value)}
          >
            {follow ? "Pause auto-follow" : "Resume auto-follow"}
          </Button>
          <Button variant="ghost" icon={<RefreshCw size={16} aria-hidden="true" />} onClick={onReconnect}>
            Reconnect
          </Button>
        </div>
      </div>
      <div className="activity-log" ref={listRef} tabIndex={0} aria-label="Run activity log">
        {entries.length ? (
          entries.map((entry) => (
            <div className={`log-entry log-entry--${entry.level}`} key={entry.id}>
              <time dateTime={entry.timestamp}>{formatTimestamp(entry.timestamp)}</time>
              <span className="log-level">{entry.level}</span>
              <span className="log-source">{entry.source ?? "system"}</span>
              <span className="log-message">{entry.message}</span>
            </div>
          ))
        ) : (
          <div className="log-empty">Waiting for activity.</div>
        )}
      </div>
    </div>
  );
}

export function RunDetailPage() {
  const { runId = "" } = useParams();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabId>("findings");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [streamKey, setStreamKey] = useState(0);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [cancelArmed, setCancelArmed] = useState(false);
  const [resumeOpen, setResumeOpen] = useState(false);
  const [resumeSecrets, setResumeSecrets] = useState<TargetSecrets>({});
  const [resumeLoadAuthorization, setResumeLoadAuthorization] = useState(false);
  const [resumeElevatedLoad, setResumeElevatedLoad] = useState(false);
  const runQuery = useQuery({
    queryKey: ["runs", runId],
    queryFn: () => api.getRun(runId),
    enabled: Boolean(runId),
    refetchInterval: (query) => (terminalStatuses.has(query.state.data?.status ?? "") ? false : 5_000),
  });

  useEffect(() => {
    if (runQuery.data?.activity) setActivity((current) => mergeActivity(current, runQuery.data.activity));
  }, [runQuery.data?.activity]);

  useEffect(() => {
    if (!runId || terminalStatuses.has(runQuery.data?.status ?? "")) {
      setStreamState("closed");
      return;
    }
    setStreamState("connecting");
    const subscription = subscribeToRun(runId, {
      onOpen: () => setStreamState("connected"),
      onError: () => setStreamState("reconnecting"),
      onEvent: (event) => {
        if (event.type === "snapshot") queryClient.setQueryData(["runs", runId], event.run);
        if (event.type === "activity") setActivity((current) => mergeActivity(current, event.entries));
      },
    });
    return subscription.close;
  }, [queryClient, runId, runQuery.data?.status, streamKey]);

  const cancelMutation = useMutation({
    mutationFn: () => api.cancelRun(runId),
    onSuccess: (run) => {
      queryClient.setQueryData(["runs", runId], run);
      setCancelArmed(false);
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    },
  });
  const resumeMutation = useMutation({
    mutationFn: (secrets?: TargetSecrets) =>
      api.resumeRun(runId, secrets, {
        authorizationConfirmed: resumeLoadAuthorization,
        elevatedLoadConfirmed: resumeElevatedLoad,
      }),
    onSuccess: (run) => {
      queryClient.setQueryData(["runs", runId], run);
      setResumeOpen(false);
      setResumeSecrets({});
      setResumeLoadAuthorization(false);
      setResumeElevatedLoad(false);
      setStreamKey((value) => value + 1);
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === "missing_secrets") setResumeOpen(true);
    },
  });

  if (runQuery.isLoading) {
    return (
      <div className="page">
        <LoadingRows count={10} />
      </div>
    );
  }
  if (runQuery.isError || !runQuery.data) {
    return (
      <div className="page">
        <ErrorState
          message={runQuery.error instanceof Error ? runQuery.error.message : "Run could not be loaded"}
          retry={() => void runQuery.refetch()}
        />
      </div>
    );
  }

  const run = runQuery.data;
  const canCancel = run.canCancel ?? ["pending", "running"].includes(run.status);
  const canResume = run.canResume ?? ["failed", "cancelled"].includes(run.status);
  const loadSettings = run.scope.httpLoad;
  const elevatedLoad = loadSettings ? isElevatedHttpLoad(loadSettings) : false;
  const lifecycleError = cancelMutation.error ?? resumeMutation.error;

  return (
    <div className="page page--run-detail">
      <PageHeader
        eyebrow={`Run ${run.workspaceId ?? run.id} · attempt ${run.attempt}`}
        title={run.targetUrl}
        actions={
          <div className="lifecycle-actions">
            {canResume ? (
              <Button
                icon={<RotateCcw size={17} aria-hidden="true" />}
                busy={resumeMutation.isPending}
                onClick={() => {
                  resumeMutation.reset();
                  if (resumeOpen) setResumeOpen(false);
                  else if (loadSettings || run.requiredSecretFields.length > 0) setResumeOpen(true);
                  else resumeMutation.mutate(undefined);
                }}
              >
                {resumeOpen ? "Close credential entry" : "Resume"}
              </Button>
            ) : null}
            {canCancel && !cancelArmed ? (
              <Button variant="danger" icon={<Square size={15} aria-hidden="true" />} onClick={() => setCancelArmed(true)}>
                Cancel run
              </Button>
            ) : null}
            {canCancel && cancelArmed ? (
              <div className="cancel-confirm" role="alert">
                <Button variant="ghost" onClick={() => setCancelArmed(false)}>
                  Keep running
                </Button>
                <Button variant="danger" busy={cancelMutation.isPending} onClick={() => cancelMutation.mutate()}>
                  Confirm cancel
                </Button>
              </div>
            ) : null}
          </div>
        }
      />

      <div className="run-identity">
        <div className="run-badges">
          <StatusBadge status={run.status} />
          <ModeBadge mode={run.sourceMode} />
          <span className="run-updated">Updated {formatTimestamp(run.updatedAt)}</span>
        </div>
        <ProgressMeter progress={run.progress} />
      </div>

      {run.sourceMode === "url-only" ? (
        <InlineNotice tone="warning" icon={<AlertTriangle size={18} aria-hidden="true" />} role="status">
          {run.coverageNotice ??
            "URL-only mode used browser and API observations; code-level coverage and source-location attribution were unavailable."}
        </InlineNotice>
      ) : null}
      {run.failure ? (
        <InlineNotice tone="danger" icon={<AlertTriangle size={18} aria-hidden="true" />} role="alert">
          {run.failure.message}
        </InlineNotice>
      ) : null}
      {canResume && resumeOpen ? (
        <form
          className="resume-secret-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (loadSettings && (!resumeLoadAuthorization || (elevatedLoad && !resumeElevatedLoad))) return;
            resumeMutation.mutate(resumeSecrets);
          }}
        >
          <div className="resume-secret-heading">
            <KeyRound size={18} aria-hidden="true" />
            <div>
              <strong>{loadSettings ? "Reconfirm this assessment attempt" : "Re-enter session-only credentials"}</strong>
              <span>
                {loadSettings
                  ? "Authorization is required again and is not written to the reusable run snapshot."
                  : "Secrets are passed to this attempt and are not written to the run snapshot."}
              </span>
            </div>
          </div>
          <div className="resume-secret-grid">
            {run.requiredSecretFields.map((field) => (
              <label className="field" key={field}>
                <span className="field-label">{secretLabels[field]}</span>
                <input
                  type="password"
                  required
                  autoComplete="off"
                  value={resumeSecrets[field] ?? ""}
                  onChange={(event) =>
                    setResumeSecrets((current) => ({ ...current, [field]: event.target.value }))
                  }
                />
              </label>
            ))}
          </div>
          {loadSettings ? (
            <div className="resume-load-confirmations">
              <label className="compact-check">
                <input
                  type="checkbox"
                  required
                  checked={resumeLoadAuthorization}
                  onChange={(event) => setResumeLoadAuthorization(event.target.checked)}
                />
                I reconfirm ownership or written authorization for this load test.
              </label>
              {elevatedLoad ? (
                <label className="compact-check">
                  <input
                    type="checkbox"
                    required
                    checked={resumeElevatedLoad}
                    onChange={(event) => setResumeElevatedLoad(event.target.checked)}
                  />
                  I reconfirm the elevated load envelope for this attempt.
                </label>
              ) : null}
            </div>
          ) : null}
          <div className="resume-secret-actions">
            <Button type="button" variant="ghost" onClick={() => setResumeOpen(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              busy={resumeMutation.isPending}
              disabled={Boolean(loadSettings && (!resumeLoadAuthorization || (elevatedLoad && !resumeElevatedLoad)))}
            >
              Resume attempt
            </Button>
          </div>
        </form>
      ) : null}
      {run.status === "completed" && !run.triageValidated ? (
        <InlineNotice tone="warning" icon={<AlertTriangle size={18} aria-hidden="true" />} role="status">
          Triage did not complete successfully. Reported findings are unvalidated.
        </InlineNotice>
      ) : null}
      {lifecycleError ? (
        <ErrorState message={lifecycleError instanceof Error ? lifecycleError.message : "Run action failed"} />
      ) : null}

      <RunMetrics run={run} />
      <PipelineTimeline stages={run.stages} />

      <section className="run-results" aria-labelledby="results-heading">
        <h2 className="sr-only" id="results-heading">
          Run results
        </h2>
        <div className="tab-list" role="tablist" aria-label="Run result views">
          {(
            [
              ["findings", `Findings ${run.findings.length}`],
              ["report", "Report"],
              ["activity", "Activity"],
            ] as Array<[TabId, string]>
          ).map(([id, label]) => (
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === id}
              aria-controls={`panel-${id}`}
              id={`tab-${id}`}
              tabIndex={activeTab === id ? 0 : -1}
              onClick={() => setActiveTab(id)}
              key={id}
            >
              {id === "activity" ? <TerminalSquare size={16} aria-hidden="true" /> : null}
              {label}
            </button>
          ))}
        </div>
        <div
          className="tab-panel"
          id={`panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`tab-${activeTab}`}
        >
          {activeTab === "findings" ? <FindingsPanel findings={run.findings} runId={run.id} /> : null}
          {activeTab === "report" ? <ReportPanel runId={run.id} artifacts={run.reportArtifacts} /> : null}
          {activeTab === "activity" ? (
            <ActivityPanel
              entries={activity}
              streamState={streamState}
              onReconnect={() => setStreamKey((value) => value + 1)}
            />
          ) : null}
        </div>
      </section>
    </div>
  );
}
