import { useQuery } from "@tanstack/react-query";
import { FlaskConical, Plus, Search } from "lucide-react";
import { useDeferredValue, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState, ErrorState, LoadingRows, PageHeader } from "../components/Primitives";
import { ModeBadge, ProgressMeter, StatusBadge } from "../components/RunStatus";
import { api } from "../lib/api";
import { formatCost, formatDuration, formatTimestamp } from "../lib/presentation";

export function RunsPage() {
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search.trim());
  const runsQuery = useQuery({
    queryKey: ["runs", deferredSearch],
    queryFn: () => api.listRuns(deferredSearch),
    refetchInterval: 5_000,
  });

  return (
    <div className="page page--runs">
      <PageHeader
        eyebrow="Assessment operations"
        title="Runs"
        actions={
          <Link to="/assessments/new" className="button button--primary">
            <Plus size={17} aria-hidden="true" />
            <span>New assessment</span>
          </Link>
        }
      />

      <div className="run-toolbar">
        <label className="search-field">
          <Search size={17} aria-hidden="true" />
          <span className="sr-only">Search runs</span>
          <input
            type="search"
            placeholder="Filter target or workspace"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <div className="result-count" aria-live="polite">
          {runsQuery.data ? `${runsQuery.data.total} ${runsQuery.data.total === 1 ? "run" : "runs"}` : ""}
        </div>
      </div>

      {runsQuery.isLoading ? <LoadingRows count={7} /> : null}
      {runsQuery.isError ? (
        <ErrorState
          message={runsQuery.error instanceof Error ? runsQuery.error.message : "Runs could not be loaded"}
          retry={() => void runsQuery.refetch()}
        />
      ) : null}
      {runsQuery.data?.items.length === 0 && !deferredSearch ? (
        <EmptyState
          icon={FlaskConical}
          title="No assessments have been run"
          action={{ label: "Configure first assessment", to: "/assessments/new" }}
        />
      ) : null}
      {runsQuery.data?.items.length === 0 && deferredSearch ? (
        <EmptyState icon={Search} title={`No runs match “${deferredSearch}”`} />
      ) : null}

      {runsQuery.data?.items.length ? (
        <div className="run-table-wrap">
          <table className="run-table">
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">Status</th>
                <th scope="col">Mode</th>
                <th scope="col">Scope</th>
                <th scope="col">Progress</th>
                <th scope="col">Time / cost</th>
              </tr>
            </thead>
            <tbody>
              {runsQuery.data.items.map((run) => (
                <tr key={run.id}>
                  <td data-label="Target">
                    <Link className="run-target" to={`/runs/${encodeURIComponent(run.id)}`}>
                      <span>{run.targetUrl}</span>
                      <small>{run.workspaceId ?? run.id}</small>
                    </Link>
                  </td>
                  <td data-label="Status">
                    <StatusBadge status={run.status} />
                  </td>
                  <td data-label="Mode">
                    <ModeBadge mode={run.sourceMode} />
                  </td>
                  <td data-label="Scope">
                    <div className="scope-summary">
                      <span>{run.scope.testCategories.length} categories</span>
                      <small>{run.scope.safeDemonstration ? "Demonstration on" : "Demonstration off"}</small>
                    </div>
                  </td>
                  <td data-label="Progress">
                    <ProgressMeter progress={run.progress} compact />
                  </td>
                  <td data-label="Time / cost">
                    <div className="time-cost">
                      <span>{formatDuration(run.metrics?.elapsedMs)}</span>
                      <small>{formatCost(run.metrics?.costUsd)}</small>
                      <small>{formatTimestamp(run.startedAt ?? run.createdAt)}</small>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
