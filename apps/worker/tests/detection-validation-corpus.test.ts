import { describe, expect, it } from 'vitest';
import { DETECTION_CORPUS_VERSION, DETECTION_VALIDATION_CORPUS } from '../src/services/detection-validation-corpus.js';
import {
  createDetectionRunMarker,
  createDetectionScenarioMarker,
  detectionCorpusHash,
  detectionFixtureHash,
} from '../src/services/detection-validation-runner.js';

describe('detection validation corpus', () => {
  it('contains five matched, inert fixtures per cohort', () => {
    expect(DETECTION_CORPUS_VERSION).toBe('1');
    expect(DETECTION_VALIDATION_CORPUS).toHaveLength(10);
    expect(DETECTION_VALIDATION_CORPUS.filter(({ cohort }) => cohort === 'ai')).toHaveLength(5);
    expect(DETECTION_VALIDATION_CORPUS.filter(({ cohort }) => cohort === 'human')).toHaveLength(5);

    const pairs = new Map<string, string[]>();
    for (const fixture of DETECTION_VALIDATION_CORPUS) {
      pairs.set(fixture.pairId, [...(pairs.get(fixture.pairId) ?? []), fixture.cohort]);
      expect(fixture.body.simulation).toBe('shannon-inert');
      expect(JSON.stringify(fixture.body)).toMatch(/\.invalid|SHANNON_FAKE|shannon-inert/);
    }
    expect([...pairs.values()]).toHaveLength(5);
    expect([...pairs.values()].every((cohorts) => cohorts.sort().join(',') === 'ai,human')).toBe(true);
  });

  it('derives stable safe markers and deterministic fixture hashes', () => {
    const fixture = DETECTION_VALIDATION_CORPUS[0];
    expect(fixture).toBeDefined();
    if (!fixture) return;

    const runMarker = createDetectionRunMarker('workflow/example');
    const scenarioMarker = createDetectionScenarioMarker('workflow/example', fixture.id);
    expect(runMarker).toMatch(/^shn-run-[a-f0-9]{24}$/);
    expect(scenarioMarker).toMatch(/^shn-sim-[a-f0-9]{24}$/);
    expect(createDetectionRunMarker('workflow/example')).toBe(runMarker);
    expect(createDetectionScenarioMarker('workflow/example', fixture.id)).toBe(scenarioMarker);
    expect(createDetectionScenarioMarker('workflow/other', fixture.id)).not.toBe(scenarioMarker);
    expect(detectionFixtureHash(fixture)).toMatch(/^[a-f0-9]{64}$/);
    expect(detectionFixtureHash(fixture)).toBe(detectionFixtureHash(structuredClone(fixture)));
    expect(DETECTION_VALIDATION_CORPUS.map(detectionFixtureHash)).toEqual([
      'c632345791c5aaf323df19214431222a918338239777091516dc168933fd714b',
      'eb1a38bad5c52b903ecec5d4c6949418a2faa53c512844a75a6beca5d6aaa561',
      '3bfb162ba38dfceb721f44664abc192e67413867b3f95904d8db0ba4f9a4ab94',
      '1430d814e4f5165b3162f1c25c3611b095de927b3f0b145937ccdfc7e25ba2b1',
      '3429cc61a9357ef4cd19603048da5818d2835f87c60dd53ae176ce56e9474d8f',
      'cf96e73f1a938a85833313f05d9b2bfba01b157e14b31e89a6f99950d8924150',
      'fba2c4b03b25a61acb4b151f57a32a55f512d320225e55e43d0bc7b4b91471eb',
      '91ded9392d8c2467b2bcc2525a846cf0a4b2895f0e63bde889b11f990ffd7acd',
      '8928b07b58725e3bc6617ae21c936ef2676c2355fad81ac502520d6df224bade',
      '3923032311bf7e84d6b659b6cb5f4cf205dcb02efa10c2fd8e7b992edee532c5',
    ]);
    expect(detectionCorpusHash()).toBe('5cb5e2a3549c955dce6922ee69714c3297e8067b52ae6c18cdb93f45cd5222e1');
  });
});
