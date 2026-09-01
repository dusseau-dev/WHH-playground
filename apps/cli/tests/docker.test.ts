import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildWorkerArgs, type WorkerOptions } from '../src/docker.js';

function options(sourceMode: 'source-assisted' | 'url-only'): WorkerOptions {
  const workspacesDir = path.resolve('/tmp/shannon-workspaces');
  return {
    version: 'test',
    repo: {
      hostPath: path.join(workspacesDir, 'assessment', '.shannon', 'runtime', 'target'),
      containerPath: sourceMode === 'url-only' ? '/app/target' : '/repos/target',
    },
    workspacesDir,
    taskQueue: 'shannon-test',
    workflowId: 'assessment-attempt-1',
    containerName: 'shannon-worker-test',
    envFlags: [],
    workspace: 'assessment',
    workingDirectory: sourceMode === 'url-only' ? '/app/target' : '/repos/target',
    sourceMode,
    labels: {
      'shannon.managed': 'true',
      'shannon.run': 'assessment',
      'shannon.workspace': 'assessment',
      'shannon.attempt': '1',
      'shannon.workflow': 'assessment-attempt-1',
    },
  };
}

function volumeMounts(args: string[]): string[] {
  return args.flatMap((argument, index) => (args[index - 1] === '-v' ? [argument] : []));
}

function environmentFlags(args: string[]): string[] {
  return args.flatMap((argument, index) => (args[index - 1] === '-e' ? [argument] : []));
}

describe('worker Docker arguments', () => {
  it('mounts the URL-only target writable and includes recovery labels', () => {
    const worker = options('url-only');
    const args = buildWorkerArgs(worker);

    expect(volumeMounts(args)).toContain(`${worker.repo.hostPath}:/app/target`);
    expect(volumeMounts(args)).not.toContain(`${worker.repo.hostPath}:/app/target:ro`);
    expect(args).toContain('shannon.managed=true');
    expect(args).toContain('shannon.workspace=assessment');
    expect(args).toContain('--workflow-id');
    expect(args).toContain('assessment-attempt-1');
    expect(args).toContain('--working-directory');
    expect(args).not.toContain('--url');
    expect(args).not.toContain('--source-mode');
    expect(args).not.toContain('--config');
    expect(args).not.toContain('--workspace');
    expect(args).not.toContain('--pipeline-testing');
    expect(volumeMounts(args)).toContain(
      `${path.join(worker.workspacesDir, worker.workspace, '.shannon', 'deliverables')}:/app/target/.shannon/deliverables`,
    );
  });

  it('retains a read-only repository mount in source-assisted mode', () => {
    const worker = options('source-assisted');
    expect(volumeMounts(buildWorkerArgs(worker))).toContain(`${worker.repo.hostPath}:/repos/target:ro`);
  });

  it('mounts selected AWS profile files read-only and remaps only their path variables', () => {
    const worker = options('source-assisted');
    worker.envFlags = [
      '-e',
      'SHANNON_AI_MODEL',
      '-e',
      'AWS_PROFILE',
      '-e',
      'AWS_SHARED_CREDENTIALS_FILE',
      '-e',
      'AWS_CONFIG_FILE',
    ];
    worker.providerCredentialFiles = [
      {
        environmentName: 'AWS_SHARED_CREDENTIALS_FILE',
        hostPath: '/host/.aws/credentials',
        containerPath: '/tmp/.aws/credentials',
      },
      {
        environmentName: 'AWS_CONFIG_FILE',
        hostPath: '/host/.aws/config',
        containerPath: '/tmp/.aws/config',
      },
    ];

    const args = buildWorkerArgs(worker);
    expect(volumeMounts(args)).toContain('/host/.aws/credentials:/tmp/.aws/credentials:ro');
    expect(volumeMounts(args)).toContain('/host/.aws/config:/tmp/.aws/config:ro');
    expect(environmentFlags(args)).toContain('AWS_PROFILE');
    expect(environmentFlags(args)).toContain('AWS_SHARED_CREDENTIALS_FILE=/tmp/.aws/credentials');
    expect(environmentFlags(args)).toContain('AWS_CONFIG_FILE=/tmp/.aws/config');
    expect(environmentFlags(args)).not.toContain('AWS_SHARED_CREDENTIALS_FILE');
    expect(environmentFlags(args)).not.toContain('AWS_CONFIG_FILE');
  });

  it('mounts and remaps a selected web-identity token without putting its value in arguments', () => {
    const worker = options('url-only');
    worker.envFlags = ['-e', 'SHANNON_AI_MODEL', '-e', 'AWS_WEB_IDENTITY_TOKEN_FILE', '-e', 'AWS_ROLE_ARN'];
    worker.providerCredentialFiles = [
      {
        environmentName: 'AWS_WEB_IDENTITY_TOKEN_FILE',
        hostPath: '/host/service-account/token',
        containerPath: '/tmp/shannon-aws-web-identity-token',
      },
    ];

    const args = buildWorkerArgs(worker);
    expect(volumeMounts(args)).toContain('/host/service-account/token:/tmp/shannon-aws-web-identity-token:ro');
    expect(environmentFlags(args)).toContain('AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/shannon-aws-web-identity-token');
    expect(environmentFlags(args)).toContain('AWS_ROLE_ARN');
    expect(environmentFlags(args)).not.toContain('AWS_WEB_IDENTITY_TOKEN_FILE');
    expect(args.join(' ')).not.toContain('token-value');
  });
});
