import type { SecretReferences, TargetSecrets, WorkflowProgress } from '../src/contracts.js';
import type { WorkerOptions } from '../src/docker.js';
import {
  type ContainerState,
  ScanController,
  type ScanRuntime,
  type SpawnProcess,
  type StartedWorkflow,
  type TemporalGateway,
  type TemporalWorkflowStart,
  type TemporalWorkflowState,
} from '../src/scan-controller.js';

export class FakeRuntime implements ScanRuntime {
  readonly launches: WorkerOptions[] = [];
  readonly stopped: string[] = [];
  prepareCalls = 0;
  unavailable = false;
  failSpawn = false;
  private readonly containers = new Map<string, ContainerState>();

  async prepare(): Promise<void> {
    this.prepareCalls++;
  }

  spawn(options: WorkerOptions): SpawnProcess {
    this.launches.push(options);
    const state: ContainerState = {
      name: options.containerName,
      running: true,
      status: 'running',
      exitCode: null,
      labels: { ...options.labels },
    };
    this.containers.set(options.containerName, state);
    const listeners = new Map<string, (...args: unknown[]) => void>();
    const process = {
      once(event: string, listener: (...args: unknown[]) => void) {
        listeners.set(event, listener);
        return process;
      },
    } as SpawnProcess;
    queueMicrotask(() => {
      if (this.failSpawn) listeners.get('exit')?.(1);
      else listeners.get('exit')?.(0);
    });
    return process;
  }

  async inspectContainer(containerName: string): Promise<ContainerState | null> {
    if (this.unavailable) throw new Error('Docker unavailable');
    return this.containers.get(containerName) ?? null;
  }

  async listManagedContainers(): Promise<ContainerState[]> {
    if (this.unavailable) throw new Error('Docker unavailable');
    return [...this.containers.values()].filter((container) => container.labels['shannon.managed'] === 'true');
  }

  async stopContainer(containerName: string): Promise<void> {
    if (this.unavailable) throw new Error('Docker unavailable');
    this.stopped.push(containerName);
    const current = this.containers.get(containerName);
    if (current) this.containers.set(containerName, { ...current, running: false, status: 'exited', exitCode: 0 });
  }

  removeContainer(containerName: string): void {
    this.containers.delete(containerName);
  }

  addContainer(container: ContainerState): void {
    this.containers.set(container.name, container);
  }
}

function progress(workflowId: string, status: WorkflowProgress['status']): WorkflowProgress {
  return {
    workflowId,
    status,
    currentPhase: status === 'running' ? 'recon' : null,
    currentAgent: status === 'running' ? 'recon' : null,
    completedAgents: [],
    failedAgent: null,
    error: status === 'failed' ? 'workflow failed' : null,
  };
}

export class FakeTemporal implements TemporalGateway {
  readonly starts: TemporalWorkflowStart[] = [];
  readonly cancelled: string[] = [];
  readonly workflows = new Map<string, TemporalWorkflowState>();
  unavailable = false;
  cancelNeverResponds = false;
  cancelResult: TemporalWorkflowState['status'] | null = 'cancelled';

  async startWorkflow(request: TemporalWorkflowStart): Promise<StartedWorkflow> {
    if (this.unavailable) throw new Error('Temporal unavailable');
    this.starts.push(request);
    this.setStatus(request.workflowId, 'running');
    return { workflowId: request.workflowId, temporalRunId: `temporal-${this.starts.length}` };
  }

  async getWorkflow(workflowId: string): Promise<TemporalWorkflowState | null> {
    if (this.unavailable) throw new Error('Temporal unavailable');
    return this.workflows.get(workflowId) ?? null;
  }

  async cancelWorkflow(workflowId: string): Promise<boolean> {
    if (this.unavailable) throw new Error('Temporal unavailable');
    this.cancelled.push(workflowId);
    if (this.cancelNeverResponds) return new Promise<boolean>(() => undefined);
    if (!this.workflows.has(workflowId)) return false;
    if (this.cancelResult) this.setStatus(workflowId, this.cancelResult);
    return true;
  }

  setStatus(workflowId: string, status: TemporalWorkflowState['status']): void {
    this.workflows.set(workflowId, { workflowId, status, progress: progress(workflowId, status) });
  }
}

export interface TestControllerOptions {
  runtime?: FakeRuntime;
  temporal?: FakeTemporal;
  cancelGraceMs?: number;
  secretValues?: Readonly<Record<string, string>>;
  secretResolver?: (references: SecretReferences) => Promise<TargetSecrets>;
}

export function testController(workspacesDir: string, options: TestControllerOptions = {}) {
  const runtime = options.runtime ?? new FakeRuntime();
  const temporal = options.temporal ?? new FakeTemporal();
  const secretValues = options.secretValues ?? {};
  const controller = new ScanController({
    version: 'test',
    workspacesDir,
    runtime,
    temporal,
    suffix: () => `attempt${runtime.launches.length + 1}`,
    credentialLoader: () => undefined,
    cancelGraceMs: options.cancelGraceMs ?? 0,
    secretResolver:
      options.secretResolver ??
      (async (references: SecretReferences): Promise<TargetSecrets> => {
        const secrets: TargetSecrets = {};
        for (const [field, reference] of Object.entries(references)) {
          const value = reference ? secretValues[reference] : undefined;
          if (value) secrets[field as keyof TargetSecrets] = value;
        }
        return secrets;
      }),
  });
  return { controller, runtime, temporal };
}
