import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, FolderInput, Play } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import {
  AssessmentConfigFields,
  assessmentDefaults,
  assessmentFormSchema,
  type AssessmentFormValues,
} from "../components/AssessmentConfigFields";
import { Button, ErrorState, PageHeader } from "../components/Primitives";
import { api } from "../lib/api";
import {
  deriveTestCategories,
  type AssessmentTestScope,
  type AssessmentTestSurface,
  type CreateRunRequest,
  type Profile,
  type ProviderConfig,
} from "../types/api";

function lines(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function selected<T extends string>(values: Record<T, boolean>): T[] {
  const result: T[] = [];
  for (const [key, enabled] of Object.entries(values) as Array<[T, boolean]>) {
    if (enabled) result.push(key);
  }
  return result;
}

function providerConfig(values: AssessmentFormValues): ProviderConfig | undefined {
  if (values.modelSource === "environment") return undefined;
  const common = { model: values.modelId, apiKey: values.providerApiKey };
  switch (values.modelSource) {
    case "openrouter":
      return {
        ...common,
        providerType: "openai",
        baseUrl: "https://openrouter.ai/api/v1",
        openAIFormat: "chat-completions",
      };
    case "anthropic":
      return { ...common, providerType: "anthropic" };
    case "openai":
      return { ...common, providerType: "openai" };
    case "xai":
      return { ...common, providerType: "xai" };
    case "custom":
      return {
        ...common,
        providerType: "generic",
        providerId: values.customProviderId,
        baseUrl: values.customBaseUrl,
        openAIFormat: values.customOpenAIFormat,
      };
  }
}

function toRequest(values: AssessmentFormValues, profileId?: string): CreateRunRequest {
  const selectedProviderConfig = providerConfig(values);
  const testScopes = selected<AssessmentTestScope>(values.testScopes);
  const testSurfaces = selected<AssessmentTestSurface>(values.testSurfaces);
  const authentication = values.authenticationEnabled
    ? {
        enabled: true,
        loginType: values.loginType,
        loginUrl: values.loginUrl,
        username: values.username,
        ...(values.email ? { email: values.email } : {}),
        ...(lines(values.loginFlow).length ? { loginFlow: lines(values.loginFlow) } : {}),
        successCondition: { type: values.successConditionType, value: values.successConditionValue },
        ...(values.password ? { password: values.password } : {}),
        ...(values.totpSecret ? { totpSecret: values.totpSecret } : {}),
      }
    : undefined;

  return {
    ...(profileId && { profileId }),
    targetUrl: values.targetUrl,
    sourceMode: values.sourceMode,
    ...(values.sourceMode === "source-assisted" ? { repoPath: values.repoPath } : {}),
    scope: {
      testCategories: deriveTestCategories(testScopes),
      testScopes,
      testSurfaces,
      safeDemonstration: values.safeDemonstration,
      concurrency: values.concurrency,
    },
    ...(selectedProviderConfig && { providerConfig: selectedProviderConfig }),
    ...(authentication ? { authentication } : {}),
    rules: {
      focus: lines(values.focusRules),
      avoid: lines(values.avoidRules),
      ...(values.rulesOfEngagement.trim() && { rulesOfEngagement: values.rulesOfEngagement.trim() }),
    },
    report: {
      ...(values.minSeverity && { minSeverity: values.minSeverity }),
      ...(values.minConfidence && { minConfidence: values.minConfidence }),
      ...(values.reportGuidance.trim() && { guidance: values.reportGuidance.trim() }),
      sarif: values.sarif,
    },
    ...(values.saveProfile ? { saveProfile: { name: values.profileName } } : {}),
    authorizationConfirmed: true,
  };
}

function profileToForm(profile: Profile): AssessmentFormValues {
  const defaults = structuredClone(assessmentDefaults);
  const selectedScopes = new Set(profile.scope.testScopes);
  const selectedSurfaces = new Set(profile.scope.testSurfaces);
  return {
    ...defaults,
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
    safeDemonstration: profile.scope.safeDemonstration,
    concurrency: profile.scope.concurrency,
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

export function NewAssessmentPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [profileLoading, setProfileLoading] = useState(false);
  const [loadedProfileId, setLoadedProfileId] = useState<string>();
  const form = useForm<AssessmentFormValues>({
    resolver: zodResolver(assessmentFormSchema),
    defaultValues: assessmentDefaults,
    mode: "onBlur",
  });
  const profilesQuery = useQuery({ queryKey: ["profiles"], queryFn: api.listProfiles });
  const launchMutation = useMutation({
    mutationFn: api.createRun,
    onSuccess: (run) => {
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      navigate(`/runs/${encodeURIComponent(run.id)}`);
    },
  });

  const loadProfile = async (profileId: string) => {
    if (!profileId) {
      setLoadedProfileId(undefined);
      form.reset(assessmentDefaults);
      return;
    }
    setProfileLoading(true);
    try {
      const profile = await queryClient.fetchQuery({
        queryKey: ["profiles", profileId],
        queryFn: () => api.getProfile(profileId),
      });
      setLoadedProfileId(profile.id);
      form.reset(profileToForm(profile));
    } finally {
      setProfileLoading(false);
    }
  };

  const submit = form.handleSubmit((values) => {
    if (!values.authorizedTesting) {
      form.setError("authorizedTesting", { message: "Authorization confirmation is required" });
      document.querySelector<HTMLInputElement>('input[name="authorizedTesting"]')?.focus();
      return;
    }
    launchMutation.mutate(toRequest(values, loadedProfileId));
  });

  return (
    <div className="page page--assessment">
      <PageHeader
        eyebrow="Run configuration"
        title="New assessment"
        actions={
          profilesQuery.data?.items.length ? (
            <label className="profile-loader">
              <FolderInput size={16} aria-hidden="true" />
              <span className="sr-only">Load profile</span>
              <select
                defaultValue=""
                disabled={profileLoading}
                onChange={(event) => void loadProfile(event.target.value)}
              >
                <option value="">Load profile…</option>
                {profilesQuery.data.items.map((profile) => (
                  <option value={profile.id} key={profile.id}>
                    {profile.name}
                  </option>
                ))}
              </select>
            </label>
          ) : null
        }
      />

      <form className="assessment-form" onSubmit={(event) => void submit(event)} noValidate>
        <AssessmentConfigFields form={form} showSaveProfile showAuthorization showModelConfig />
        {form.formState.errors.authorizedTesting ? (
          <div className="form-submit-error" role="alert">
            {form.formState.errors.authorizedTesting.message}
          </div>
        ) : null}
        {launchMutation.isError ? (
          <ErrorState
            message={
              launchMutation.error instanceof Error ? launchMutation.error.message : "Assessment could not be started"
            }
          />
        ) : null}
        <footer className="form-footer">
          <div className="launch-summary" aria-live="polite">
            <Play size={16} aria-hidden="true" />
            {selected(form.watch("testScopes")).length} checks · concurrency {form.watch("concurrency")}
          </div>
          <Button
            type="submit"
            variant="primary"
            icon={<ArrowRight size={17} aria-hidden="true" />}
            busy={launchMutation.isPending}
          >
            Start assessment
          </Button>
        </footer>
      </form>
    </div>
  );
}
