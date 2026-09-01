import {
  AlertCircle,
  Ban,
  Check,
  Clock3,
  LoaderCircle,
  Minus,
  X,
} from "lucide-react";
import { clampProgress, statusLabel } from "../lib/presentation";
import type { RunProgress, RunStatus, SourceMode, StageStatus } from "../types/api";

const statusIcons = {
  pending: Clock3,
  running: LoaderCircle,
  completed: Check,
  failed: AlertCircle,
  cancelled: X,
} satisfies Record<RunStatus, typeof Check>;

export function StatusBadge({ status }: { status: RunStatus }) {
  const Icon = statusIcons[status];
  return (
    <span className={`status-badge status-badge--${status}`}>
      <Icon className={status === "running" ? "spin" : undefined} size={14} aria-hidden="true" />
      <span>{statusLabel(status)}</span>
    </span>
  );
}

export function ModeBadge({ mode }: { mode: SourceMode }) {
  return (
    <span className={`mode-badge mode-badge--${mode}`}>
      {mode === "url-only" ? "URL only" : "Source assisted"}
    </span>
  );
}

export function ProgressMeter({ progress, compact = false }: { progress: RunProgress; compact?: boolean }) {
  const percent = clampProgress(progress);
  return (
    <div className={`progress-meter${compact ? " progress-meter--compact" : ""}`}>
      <div className="progress-track" aria-hidden="true">
        <span style={{ transform: `scaleX(${percent / 100})` }} />
      </div>
      <span className="progress-value">{percent}%</span>
      <span className="sr-only">
        {progress.completed} of {progress.total} stages complete
      </span>
    </div>
  );
}

const stageIcons = {
  pending: Clock3,
  running: LoaderCircle,
  completed: Check,
  failed: AlertCircle,
  skipped: Ban,
  cancelled: X,
  unavailable: Minus,
} satisfies Record<StageStatus, typeof Check>;

export function StageIcon({ status }: { status: StageStatus }) {
  const Icon = stageIcons[status];
  return (
    <span className={`stage-icon stage-icon--${status}`} title={status}>
      <Icon className={status === "running" ? "spin" : undefined} size={15} aria-label={status} />
    </span>
  );
}
