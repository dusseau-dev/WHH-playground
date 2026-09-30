import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileUp, KeyRound, Plus, Save, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import {
  AssessmentConfigFields,
  assessmentDefaults,
  assessmentFormSchema,
  type AssessmentFormValues,
} from "../components/AssessmentConfigFields";
import { Button, EmptyState, ErrorState, LoadingRows, PageHeader } from "../components/Primitives";
import { ModeBadge } from "../components/RunStatus";
import { api } from "../lib/api";
import { formatTimestamp } from "../lib/presentation";
import {
  deriveTestCategories,
  type AssessmentModule,
  type AssessmentTestScope,
  type AssessmentTestSurface,
  HTTP_LOAD_SCOPE,
  type Profile,
  type SaveProfileRequest,
} from "../types/api";

function list(value: string): string[] {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

function selected<T extends string>(values: Record<T, boolean>): T[] {
  const result: T[] = [];
  for (const [key, enabled] of Object.entries(values) as Array<[T, boolean]>) {
    if (enabled) result.push(key);
  }
  return result;
}

function profileValues(profile: Profile): AssessmentFormValues {
  const defaults = structuredClone(assessmentDefaults);
  const selectedScopes = new Set(profile.scope.testScopes);
  const selectedSurfaces = new Set(profile.scope.testSurfaces);
  const selectedModules = new Set(profile.scope.assessmentModules);
  if (selectedModules.delete(HTTP_LOAD_SCOPE)) selectedScopes.add(HTTP_LOAD_SCOPE);
  return {
    ...defaults,
    name: profile.name,
    targetUrl: profile.targetUrl,
    sourceMode: profile.sourceMode,
    repoPath: profile.repoPath ?? "",
    testScopes: Object.fromEntries(
      Object.keys(defaults.testScopes).map((key) => [
        key,
        selectedScopes.has(key as AssessmentTestScope),
      ]),
    ) as AssessmentFormValues["testScopes"],
    testSurfaces: Object.fromEntries(
      Object.keys(defaults.testSurfaces).map((key) => [
        key,
        selectedSurfaces.has(key as AssessmentTestSurface),
      ]),
    ) as AssessmentFormValues["testSurfaces"],
    assessmentModules: Object.fromEntries(
      Object.keys(defaults.assessmentModules).map((key) => [key, selectedModules.has(key as AssessmentModule)]),
    ) as AssessmentFormValues["assessmentModules"],
    targetEnvironment: profile.scope.moduleSafety.targetEnvironment,
    allowActiveDast: profile.scope.moduleSafety.allowActiveDast,
    acknowledgeLoadRisk: profile.scope.moduleSafety.acknowledgeLoadRisk,
    moduleMaxRequestsPerSecond: profile.scope.moduleSafety.maxRequestsPerSecond,
    moduleMaxConcurrency: profile.scope.moduleSafety.maxConcurrency,
    loadStageDurationSeconds: profile.scope.moduleSafety.loadStageDurationSeconds,
    loadErrorRateThreshold: profile.scope.moduleSafety.loadErrorRateThreshold,
    loadP95LatencyMsThreshold: profile.scope.moduleSafety.loadP95LatencyMsThreshold,
    safeDemonstration: profile.scope.safeDemonstration,
    concurrency: profile.scope.concurrency,
    httpLoadConcurrency: profile.scope.httpLoad?.concurrency ?? defaults.httpLoadConcurrency,
    httpLoadRequestsPerSecond: profile.scope.httpLoad?.requestsPerSecond ?? defaults.httpLoadRequestsPerSecond,
    httpLoadDurationSeconds: profile.scope.httpLoad?.durationSeconds ?? defaults.httpLoadDurationSeconds,
    elevatedLoadConfirmed: false,
    detectionCanaryPath: profile.scope.detectionValidation?.canaryPath ?? defaults.detectionCanaryPath,
    detectionMinimumRate: profile.scope.detectionValidation?.minimumDetectionRate ?? defaults.detectionMinimumRate,
    detectionMaxWaitSeconds: profile.scope.detectionValidation?.maxWaitSeconds ?? defaults.detectionMaxWaitSeconds,
    splunkManagementUrl: profile.scope.detectionValidation?.splunk.managementUrl ?? "",
    splunkTelemetryIndex: profile.scope.detectionValidation?.splunk.telemetryIndex ?? "",
    splunkAlertIndex: profile.scope.detectionValidation?.splunk.alertIndex ?? "",
    splunkTelemetrySourcetype: profile.scope.detectionValidation?.splunk.telemetrySourcetype ?? "",
    splunkAlertSourcetype: profile.scope.detectionValidation?.splunk.alertSourcetype ?? "",
    splunkToken: "",
    hasStoredSplunkToken: profile.secretState.splunkToken.present,
    clearSplunkToken: false,
    authenticationEnabled: profile.authentication?.enabled ?? false,
    loginType: profile.authentication?.loginType ?? "form",
    loginUrl: profile.authentication?.loginUrl ?? "",
    username: profile.authentication?.username ?? "",
    email: profile.authentication?.email ?? "",
    loginFlow: profile.authentication?.loginFlow?.join("\n") ?? "",
    successConditionType: profile.authentication?.successCondition.type ?? "url_contains",
    successConditionValue: profile.authentication?.successCondition.value ?? "",
    focusRules: profile.rules.focus.join("\n"),
    avoidRules: profile.rules.avoid.join("\n"),
    rulesOfEngagement: profile.rules.rulesOfEngagement ?? "",
    minSeverity: profile.report.minSeverity ?? "",
    minConfidence: profile.report.minConfidence ?? "",
    reportGuidance: profile.report.guidance ?? "",
    sarif: profile.report.sarif ?? false,
  };
}

function profileRequest(values: AssessmentFormValues): SaveProfileRequest {
  const testScopes = selected<AssessmentTestScope>(values.testScopes);
  const testSurfaces = selected<AssessmentTestSurface>(values.testSurfaces);
  const assessmentModules = selected<AssessmentModule>(values.assessmentModules);
  const authentication = values.authenticationEnabled
    ? {
        enabled: true,
        loginType: values.loginType,
        loginUrl: values.loginUrl,
        username: values.username,
        ...(values.email ? { email: values.email } : {}),
        ...(list(values.loginFlow).length ? { loginFlow: list(values.loginFlow) } : {}),
        successCondition: { type: values.successConditionType, value: values.successConditionValue },
        ...(values.password ? { password: values.password } : {}),
        ...(values.totpSecret ? { totpSecret: values.totpSecret } : {}),
      }
    : undefined;
  const clearSecrets = [
    values.clearPassword ? "password" : undefined,
    values.clearTotp ? "totpSecret" : undefined,
    values.clearSplunkToken ? "splunkToken" : undefined,
  ].filter((value): value is "password" | "totpSecret" | "splunkToken" => Boolean(value));
  return {
    name: values.name,
    targetUrl: values.targetUrl,
    sourceMode: values.sourceMode,
    ...(values.sourceMode === "source-assisted" ? { repoPath: values.repoPath } : {}),
    scope: {
      testCategories: deriveTestCategories(testScopes),
      testScopes,
      testSurfaces,
      safeDemonstration: values.safeDemonstration,
      concurrency: values.concurrency,
      ...(testScopes.includes("alerting-effectiveness") && {
        detectionValidation: {
          canaryPath: values.detectionCanaryPath,
          minimumDetectionRate: values.detectionMinimumRate,
          maxWaitSeconds: values.detectionMaxWaitSeconds,
          splunk: {
            managementUrl: values.splunkManagementUrl,
            telemetryIndex: values.splunkTelemetryIndex,
            alertIndex: values.splunkAlertIndex,
            ...(values.splunkTelemetrySourcetype && { telemetrySourcetype: values.splunkTelemetrySourcetype }),
            ...(values.splunkAlertSourcetype && { alertSourcetype: values.splunkAlertSourcetype }),
          },
        },
      }),
      assessmentModules,
      moduleSafety: {
        targetEnvironment: values.targetEnvironment,
        allowActiveDast: values.allowActiveDast,
        acknowledgeLoadRisk: values.acknowledgeLoadRisk,
        maxRequestsPerSecond: values.moduleMaxRequestsPerSecond,
        maxConcurrency: values.moduleMaxConcurrency,
        loadStageDurationSeconds: values.loadStageDurationSeconds,
        loadErrorRateThreshold: values.loadErrorRateThreshold,
        loadP95LatencyMsThreshold: values.loadP95LatencyMsThreshold,
      },
    },
    ...(authentication ? { authentication } : {}),
    ...(values.splunkToken ? { secrets: { splunkToken: values.splunkToken } } : {}),
    rules: {
      focus: list(values.focusRules),
      avoid: list(values.avoidRules),
      ...(values.rulesOfEngagement.trim() && { rulesOfEngagement: values.rulesOfEngagement.trim() }),
    },
    report: {
      ...(values.minSeverity && { minSeverity: values.minSeverity }),
      ...(values.minConfidence && { minConfidence: values.minConfidence }),
      ...(values.reportGuidance.trim() && { guidance: values.reportGuidance.trim() }),
      sarif: values.sarif,
    },
    ...(clearSecrets.length ? { clearSecrets } : {}),
  };
}

export function ProfilesPage() {
  const queryClient = useQueryClient();
  const importInput = useRef<HTMLInputElement>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const profilesQuery = useQuery({ queryKey: ["profiles"], queryFn: api.listProfiles });
  const profileQuery = useQuery({
    queryKey: ["profiles", selectedId],
    queryFn: () => api.getProfile(selectedId ?? ""),
    enabled: Boolean(selectedId),
  });
  const form = useForm<AssessmentFormValues>({
    resolver: zodResolver(assessmentFormSchema),
    defaultValues: assessmentDefaults,
    mode: "onBlur",
  });

  useEffect(() => {
    if (profileQuery.data) form.reset(profileValues(profileQuery.data));
  }, [form, profileQuery.data]);

  const saveMutation = useMutation({
    mutationFn: async (values: AssessmentFormValues) => {
      if (!values.name.trim()) throw new Error("Profile name is required");
      return selectedId ? api.updateProfile(selectedId, profileRequest(values)) : api.createProfile(profileRequest(values));
    },
    onSuccess: (profile) => {
      setSelectedId(profile.id);
      setCreating(false);
      form.reset(profileValues(profile));
      void queryClient.invalidateQueries({ queryKey: ["profiles"] });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteProfile(id),
    onSuccess: () => {
      setSelectedId(null);
      setConfirmDelete(false);
      form.reset(assessmentDefaults);
      void queryClient.invalidateQueries({ queryKey: ["profiles"] });
    },
  });
  const importMutation = useMutation({
    mutationFn: async (file: File) => api.importProfile(await file.text()),
    onSuccess: (profile) => {
      setSelectedId(profile.id);
      setCreating(false);
      void queryClient.invalidateQueries({ queryKey: ["profiles"] });
    },
  });

  const beginCreate = () => {
    setCreating(true);
    setSelectedId(null);
    setConfirmDelete(false);
    form.reset(assessmentDefaults);
  };

  const openProfile = (id: string) => {
    setCreating(false);
    setSelectedId(id);
    setConfirmDelete(false);
  };

  const hasEditor = creating || selectedId !== null;
  const activeProfile = profileQuery.data;

  return (
    <div className="page page--profiles">
      <PageHeader
        eyebrow="Reusable configuration"
        title="Profiles"
        actions={
          <div className="button-group">
            <input
              ref={importInput}
              className="visually-hidden-input"
              type="file"
              accept=".yaml,.yml,text/yaml,application/yaml"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) importMutation.mutate(file);
                event.currentTarget.value = "";
              }}
            />
            <Button icon={<FileUp size={17} aria-hidden="true" />} onClick={() => importInput.current?.click()}>
              Import
            </Button>
            <Button variant="primary" icon={<Plus size={17} aria-hidden="true" />} onClick={beginCreate}>
              New profile
            </Button>
          </div>
        }
      />

      {importMutation.isError ? (
        <ErrorState
          message={importMutation.error instanceof Error ? importMutation.error.message : "Profile import failed"}
        />
      ) : null}

      <div className="profiles-layout">
        <section className="profile-list" aria-label="Saved profiles">
          {profilesQuery.isLoading ? <LoadingRows count={5} /> : null}
          {profilesQuery.isError ? (
            <ErrorState
              message={profilesQuery.error instanceof Error ? profilesQuery.error.message : "Profiles could not be loaded"}
              retry={() => void profilesQuery.refetch()}
            />
          ) : null}
          {profilesQuery.data?.items.length === 0 ? (
            <EmptyState icon={KeyRound} title="No saved profiles" />
          ) : null}
          {profilesQuery.data?.items.map((profile) => (
            <button
              type="button"
              className={`profile-list-item${selectedId === profile.id ? " profile-list-item--active" : ""}`}
              key={profile.id}
              onClick={() => openProfile(profile.id)}
              aria-pressed={selectedId === profile.id}
            >
              <span className="profile-list-main">
                <strong>{profile.name}</strong>
                <small>{profile.targetUrl}</small>
              </span>
              <span className="profile-list-meta">
                <ModeBadge mode={profile.sourceMode} />
                <small>{formatTimestamp(profile.updatedAt)}</small>
              </span>
              <span className="secret-summary" aria-label="Credential storage">
                <KeyRound size={14} aria-hidden="true" />
                {profile.secretState.password.present || profile.secretState.totp.present ? "Stored" : "No secrets"}
              </span>
            </button>
          ))}
        </section>

        <section className="profile-editor" aria-label="Profile editor">
          {!hasEditor ? (
            <div className="editor-blank">
              <KeyRound size={22} aria-hidden="true" />
              <span>Select a profile to edit</span>
            </div>
          ) : null}
          {selectedId && profileQuery.isLoading ? <LoadingRows count={7} /> : null}
          {selectedId && profileQuery.isError ? (
            <ErrorState
              message={profileQuery.error instanceof Error ? profileQuery.error.message : "Profile could not be loaded"}
              retry={() => void profileQuery.refetch()}
            />
          ) : null}
          {(creating || activeProfile) && !profileQuery.isLoading ? (
            <form
              className="profile-form"
              onSubmit={(event) => void form.handleSubmit((values) => saveMutation.mutateAsync(values))(event)}
              noValidate
            >
              <div className="profile-editor-bar">
                <div>
                  <span className="eyebrow">{creating ? "Unsaved" : "Profile"}</span>
                  <h2>{creating ? "New profile" : activeProfile?.name}</h2>
                </div>
                <div className="button-group">
                  {activeProfile ? (
                    <a
                      className="icon-button"
                      href={api.profileExportUrl(activeProfile.id)}
                      download={`${activeProfile.name}.yaml`}
                      aria-label="Export profile"
                      title="Export profile"
                    >
                      <Download size={18} aria-hidden="true" />
                    </a>
                  ) : null}
                  {activeProfile && !confirmDelete ? (
                    <button
                      className="icon-button icon-button--danger"
                      type="button"
                      aria-label="Delete profile"
                      title="Delete profile"
                      onClick={() => setConfirmDelete(true)}
                    >
                      <Trash2 size={18} aria-hidden="true" />
                    </button>
                  ) : null}
                </div>
              </div>
              {confirmDelete && activeProfile ? (
                <div className="delete-confirm" role="alert">
                  <span>Delete {activeProfile.name}?</span>
                  <div className="button-group">
                    <Button type="button" variant="ghost" onClick={() => setConfirmDelete(false)}>
                      Keep
                    </Button>
                    <Button
                      type="button"
                      variant="danger"
                      busy={deleteMutation.isPending}
                      onClick={() => deleteMutation.mutate(activeProfile.id)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              ) : null}
              <AssessmentConfigFields
                form={form}
                showProfileName
                passwordState={activeProfile?.secretState.password}
                totpState={activeProfile?.secretState.totp}
                splunkTokenState={activeProfile?.secretState.splunkToken}
              />
              {saveMutation.isError ? (
                <ErrorState
                  message={saveMutation.error instanceof Error ? saveMutation.error.message : "Profile could not be saved"}
                />
              ) : null}
              <footer className="profile-form-footer">
                <Button
                  type="submit"
                  variant="primary"
                  icon={<Save size={17} aria-hidden="true" />}
                  busy={saveMutation.isPending}
                >
                  Save profile
                </Button>
              </footer>
            </form>
          ) : null}
        </section>
      </div>
    </div>
  );
}
