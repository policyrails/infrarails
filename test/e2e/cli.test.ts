import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

function hcl2jsonAvailable(): boolean {
  try {
    execSync('hcl2json --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const describeIf = hcl2jsonAvailable() ? describe : describe.skip;

const cliPath = path.resolve(__dirname, '../../dist/index.js');
const fixturesDir = path.resolve(__dirname, '../fixtures');

function runCli(
  args: string,
): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`node ${cliPath} ${args}`, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout || '',
      stderr: err.stderr || '',
      exitCode: err.status ?? 1,
    };
  }
}

const combosDir = path.resolve(__dirname, '../fixtures/bedrock-logging-combos');

describeIf('CLI e2e', () => {
  it('should exit 0 for compliant fixtures', () => {
    const result = runCli(`${fixturesDir}/compliant`);
    expect(result.exitCode).toBe(0);
  });

  it('should exit 1 for non-compliant fixtures', () => {
    const result = runCli(`${fixturesDir}/non-compliant`);
    expect(result.exitCode).toBe(1);
  });

  it('should exit 1 for partial fixtures (has WARNs)', () => {
    const result = runCli(`${fixturesDir}/partial`);
    expect(result.exitCode).toBe(1);
  });

  it('should output valid JSON with --format json', () => {
    const result = runCli(`${fixturesDir}/non-compliant --format json`);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.summary).toBeDefined();
    expect(parsed.findings).toBeDefined();
    expect(parsed.summary.fail).toBeGreaterThan(0);
  });

  it('should output valid SARIF 2.1.0 with --format sarif', () => {
    const result = runCli(`${fixturesDir}/non-compliant --format sarif`);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe('infrarails');
    expect(parsed.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
    const errorResults = parsed.runs[0].results.filter(
      (r: { level: string }) => r.level === 'error',
    );
    expect(errorResults.length).toBeGreaterThan(0);
    // Every result references a rule that exists in the driver catalogue.
    const ruleIds = new Set<string>(
      parsed.runs[0].tool.driver.rules.map((r: { id: string }) => r.id),
    );
    for (const r of parsed.runs[0].results as { ruleId: string }[]) {
      expect(ruleIds.has(r.ruleId)).toBe(true);
    }
  });

  it('rejects unknown formats with exit 2', () => {
    const result = runCli(`${fixturesDir}/compliant --format bogus`);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toMatch(/unknown format/i);
  });

  it('should exit 0 for directory with no .tf files', () => {
    const emptyDir = path.resolve(__dirname, '../../node_modules/.cache');
    execSync(`mkdir -p ${emptyDir}`);
    const result = runCli(emptyDir);
    expect(result.exitCode).toBe(0);
  });

  // Bedrock logging combo fixtures
  it('combo 1 (s3-only): should exit 0 for fully compliant s3-only config', () => {
    const result = runCli(`${combosDir}/s3-only`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 2 (cw-only): should exit 0 for fully compliant cloudwatch-only config', () => {
    const result = runCli(`${combosDir}/cw-only`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 3 (cw-and-s3): should exit 0 for fully compliant cloudwatch+s3 config', () => {
    const result = runCli(`${combosDir}/cw-and-s3`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 4 (cw-large-data): should exit 0 for fully compliant cloudwatch+large-data-s3 config', () => {
    const result = runCli(`${combosDir}/cw-large-data`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 5 (cw-s3-large-data): should exit 0 for fully compliant cloudwatch+s3+large-data-s3 config', () => {
    const result = runCli(`${combosDir}/cw-s3-large-data`);
    expect(result.exitCode).toBe(0);
  });

  it('usage-no-logging (default permissive): Bedrock resources without invocation logging should be INCONCLUSIVE', () => {
    const result = runCli(`${combosDir}/usage-no-logging --format json`);
    expect(result.exitCode).toBe(1); // INCONCLUSIVE blocks in default strict mode
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('INCONCLUSIVE');
    expect(finding?.description).toMatch(/aws_bedrockagent_agent|aws_bedrock_guardrail/);
  });

  it('usage-no-logging --strict-account-logging: should FAIL S-12.1.1', () => {
    const result = runCli(`${combosDir}/usage-no-logging --strict-account-logging --format json`);
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('FAIL');
    expect(finding?.description).toMatch(/Strict account-logging mode/);
  });

  it('no-usage-no-logging: no Bedrock anywhere should SKIP S-12.1.1 (exit 0)', () => {
    const result = runCli(`${combosDir}/no-usage-no-logging --format json`);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('SKIP');
    expect(result.exitCode).toBe(0);
  });

  describe('Fix 1 / Fix 3 / Fix 4 e2e fixtures', () => {
    it('iam-only-no-logging: IAM grant only → INCONCLUSIVE (Fix 3a)', () => {
      const result = runCli(`${combosDir}/iam-only-no-logging --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
      expect(finding?.description).toMatch(/IAM grant/);
      expect(finding?.description).toContain('bedrock:InvokeModel');
    });

    it('iam-policy-document-only: data source policy with bedrock action → INCONCLUSIVE', () => {
      const result = runCli(`${combosDir}/iam-policy-document-only --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
      expect(finding?.description).toContain('data.aws_iam_policy_document.bedrock_converse');
    });

    it('vpc-endpoint-only: VPC endpoint to bedrock-runtime → INCONCLUSIVE (Fix 3b)', () => {
      const result = runCli(`${combosDir}/vpc-endpoint-only --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
      expect(finding?.description).toContain('aws_vpc_endpoint.bedrock');
      expect(finding?.description).toContain('bedrock-runtime');
    });

    it('data-source-only: aws_bedrock_foundation_model data source → INCONCLUSIVE (Fix 3c)', () => {
      const result = runCli(`${combosDir}/data-source-only --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
      expect(finding?.description).toContain('data.aws_bedrock_foundation_model.claude');
    });

    it('json-format: .tf.json fixture is parsed and S-12.1.1 PASSES (Fix 1)', () => {
      const result = runCli(`${combosDir}/json-format --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('PASS');
    });

    it('strict-mode-fail (default): direct usage no logging → INCONCLUSIVE', () => {
      const result = runCli(`${combosDir}/strict-mode-fail --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
    });

    it('strict-mode-fail --strict-account-logging: direct usage no logging → FAIL', () => {
      const result = runCli(`${combosDir}/strict-mode-fail --strict-account-logging --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('FAIL');
      expect(finding?.description).toMatch(/Strict account-logging mode/);
    });

    it('remote-module-bedrock-logging (default): direct Bedrock + no logging in scanned files → INCONCLUSIVE', () => {
      const result = runCli(`${combosDir}/remote-module-bedrock-logging --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
      // No naming-based suppression: the verdict does not cite the module name
      // or the log_bucket input as evidence of external logging.
      expect(finding?.description).not.toMatch(/module call/);
      expect(finding?.description).not.toMatch(/cross-stack/);
    });

    it('remote-module-bedrock-logging --strict-account-logging: → FAIL (no heuristic suppression)', () => {
      const result = runCli(
        `${combosDir}/remote-module-bedrock-logging --strict-account-logging --format json`,
      );
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('FAIL');
      expect(finding?.description).toMatch(/Strict account-logging mode/);
    });

    it('cross-stack-baseline-logging (default): direct Bedrock + remote-state ref → INCONCLUSIVE without naming the stack', () => {
      const result = runCli(`${combosDir}/cross-stack-baseline-logging --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('INCONCLUSIVE');
      expect(finding?.description).not.toMatch(/baseline remote-state/);
      expect(finding?.description).not.toMatch(/cross-stack/);
    });

    it('cross-stack-baseline-logging --strict-account-logging: → FAIL (no heuristic suppression)', () => {
      const result = runCli(
        `${combosDir}/cross-stack-baseline-logging --strict-account-logging --format json`,
      );
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('FAIL');
      expect(finding?.description).toMatch(/Strict account-logging mode/);
    });

    it('bedrock-named-local-module: PASS (regression guard — local module logging is found)', () => {
      const result = runCli(`${combosDir}/bedrock-named-local-module --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('PASS');
    });

    it('expanded-resource-types: new Bedrock types in finite list are detected → PASS (Fix 2)', () => {
      const result = runCli(`${combosDir}/expanded-resource-types --format json`);
      const parsed = JSON.parse(result.stdout);
      const finding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(finding?.status).toBe('PASS');
    });
  });

  it('usage-logging-all-disabled: all modality toggles false should FAIL S-12.1.1', () => {
    const result = runCli(`${combosDir}/usage-logging-all-disabled --format json`);
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('FAIL');
    expect(finding?.description).toMatch(/every \*_data_delivery_enabled toggle/i);
  });

  it('regression: large-data bucket with no lifecycle should fail S-12.1.2b', () => {
    const result = runCli(
      `${fixturesDir}/non-compliant/cw-large-data-missing-lifecycle --format json`,
    );
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    const lifecycleFinding = parsed.findings.find(
      (f: { ruleId: string; status: string }) =>
        f.ruleId === 'S-12.1.2b' && f.status === 'FAIL',
    );
    expect(lifecycleFinding).toBeDefined();
  });

  describe('module handling', () => {
    const moduleAuditDir = path.resolve(__dirname, '../fixtures/module-audit');

    it('local-module-logging-inside: resources in local module are fully scanned (exit 0)', () => {
      const result = runCli(`${moduleAuditDir}/local-module-logging-inside --format json`);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.stdout);
      const bedrockFinding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(bedrockFinding?.status).toBe('PASS');
    });

    it('remote-module-invisible: S-12.1.1 INCONCLUSIVE and S-12.x.5 INCONCLUSIVE (exit 1)', () => {
      const result = runCli(`${moduleAuditDir}/remote-module-invisible --format json`);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.stdout);

      const s1 = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.1.1');
      expect(s1?.status).toBe('INCONCLUSIVE');

      const s5 = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.x.5');
      expect(s5?.status).toBe('INCONCLUSIVE');
      expect(s5?.description).toContain('terraform-aws-modules/bedrock/aws');
    });

    it('var-scope-bleed: child var with no default resolves to INCONCLUSIVE, not parent default', () => {
      const result = runCli(`${moduleAuditDir}/var-scope-bleed --format json`);
      const parsed = JSON.parse(result.stdout);
      const lifecycle = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.2b',
      );
      // With scope fix: child var.log_bucket has no default → INCONCLUSIVE
      // Without fix it would resolve to "parent-log-bucket" and FAIL
      expect(lifecycle?.status).toBe('INCONCLUSIVE');
    });
  });

  describe('--plan flag', () => {
    const planDir = path.resolve(__dirname, '../fixtures/plan-mode');

    it('var-resolved: --plan eliminates the INCONCLUSIVE that source-only mode emits', () => {
      const without = runCli(`${planDir}/var-resolved --format json`);
      const withPlan = runCli(
        `${planDir}/var-resolved --plan ${planDir}/var-resolved/plan.json --format json`,
      );
      const w0 = JSON.parse(without.stdout);
      const w1 = JSON.parse(withPlan.stdout);
      expect(w0.summary.inconclusive).toBeGreaterThan(0);
      expect(w1.summary.inconclusive).toBe(0);
      expect(w1.summary.fail).toBe(0);
      expect(withPlan.exitCode).toBe(0);
    });

    it('complex-interpolation: --plan resolves bucket/log group via containing-resource fallback', () => {
      const without = runCli(`${planDir}/complex-interpolation --format json`);
      const withPlan = runCli(
        `${planDir}/complex-interpolation --plan ${planDir}/complex-interpolation/plan.json --format json`,
      );
      const w0 = JSON.parse(without.stdout);
      const w1 = JSON.parse(withPlan.stdout);
      expect(w0.summary.inconclusive).toBeGreaterThan(0);
      expect(w1.summary.inconclusive).toBe(0);
      expect(w1.summary.fail).toBe(0);
      expect(withPlan.exitCode).toBe(0);
    });

    it('computed-bucket: bucket marked after_unknown stays INCONCLUSIVE (plan-known-after-apply), not FAIL', () => {
      const result = runCli(
        `${planDir}/computed-bucket --plan ${planDir}/computed-bucket/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);
      const matched = parsed.findings.filter((f: { description: string }) =>
        /known at apply time|after_unknown|computed at apply/i.test(
          f.description,
        ),
      );
      expect(matched.length).toBeGreaterThan(0);
      // No spurious FAIL from comparing null against the rule expectation
      const fails = parsed.findings.filter(
        (f: { status: string; description: string }) =>
          f.status === 'FAIL' && /bucket/i.test(f.description),
      );
      expect(fails.length).toBe(0);
    });

    it('deletion-of-logging: destroying the bedrock logging config emits a FAIL', () => {
      const result = runCli(
        `${planDir}/deletion-of-logging --plan ${planDir}/deletion-of-logging/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);
      const delFinding = parsed.findings.find(
        (f: { ruleId: string; status: string }) =>
          f.ruleId === 'S-12.x.del' && f.status === 'FAIL',
      );
      expect(delFinding).toBeDefined();
      expect(delFinding.description).toMatch(/destruction/);
      expect(result.exitCode).toBe(1);
    });

    it('remote-module-only: resources buried in a remote module are evaluated via the overlay', () => {
      const result = runCli(
        `${planDir}/remote-module-only --plan ${planDir}/remote-module-only/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);
      const bedrock = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(bedrock?.status).toBe('PASS');
      // plan-sourced citation on the discovered resource
      expect(bedrock?.filePath).toMatch(/^plan:module\.bedrock_logging\./);
    });

    it('missing plan file: exits 2 with clear stderr', () => {
      const result = runCli(
        `${planDir}/var-resolved --plan ${planDir}/var-resolved/does-not-exist.json --format json`,
      );
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/plan file not found/i);
    });

    it('malformed plan JSON: exits 2', () => {
      const result = runCli(
        `${planDir}/var-resolved --plan ${planDir}/bad-plans/malformed.txt --format json`,
      );
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/not valid JSON|format_version/);
    });

    it('errored plan: exits 2 with explicit message', () => {
      const result = runCli(
        `${planDir}/var-resolved --plan ${planDir}/bad-plans/errored.json --format json`,
      );
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/errored state/);
    });

    it('remote-module-toggles-disabled: plan-buried logging config with all toggles false → S-12.1.1 FAIL', () => {
      const result = runCli(
        `${planDir}/remote-module-toggles-disabled --plan ${planDir}/remote-module-toggles-disabled/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);
      const bedrock = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(bedrock?.status).toBe('FAIL');
      expect(bedrock?.description).toMatch(/every \*_data_delivery_enabled toggle/i);
      expect(bedrock?.filePath).toMatch(
        /^plan:module\.bedrock_governance\.aws_bedrock_model_invocation_logging_configuration/,
      );
      expect(result.exitCode).toBe(1);
    });

    it('remote-module-broken-supporting: plan-buried logging w/ broken S3 + short retention → multiple FAILs and a WARN', () => {
      const result = runCli(
        `${planDir}/remote-module-broken-supporting --plan ${planDir}/remote-module-broken-supporting/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);

      const bedrock = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(bedrock?.status).toBe('PASS');

      // S3 encryption missing → FAIL
      const enc = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.x.2a');
      expect(enc?.status).toBe('FAIL');
      expect(enc?.description).toContain('remote-module-bedrock-logs');

      // S3 versioning disabled → FAIL
      const vers = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.x.1');
      expect(vers?.status).toBe('FAIL');
      expect(vers?.description).toContain('remote-module-bedrock-logs');

      // S3 lifecycle missing → FAIL
      const lc = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.1.2b');
      expect(lc?.status).toBe('FAIL');
      expect(lc?.description).toContain('remote-module-bedrock-logs');

      // CW retention below floor → WARN (rule emits WARN unless --strict-account-logging)
      const cw = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.1.2a');
      expect(cw?.status).toBe('WARN');
      expect(cw?.description).toMatch(/30 days|below the 180-day floor/i);

      expect(result.exitCode).toBe(1);
    });

    it('sensitive-bucket: after_sensitive marks the bucket attribute → bucket-scoped rules INCONCLUSIVE with plan-sensitive-redacted (never FAIL on "(sensitive value)")', () => {
      const result = runCli(
        `${planDir}/sensitive-bucket --plan ${planDir}/sensitive-bucket/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);

      const sensitiveFindings = parsed.findings.filter(
        (f: { unresolvedReason?: string }) =>
          f.unresolvedReason === 'plan-sensitive-redacted',
      );
      // At least the S3 encryption / versioning / lifecycle rules read the
      // bucket reference and should bail out with the sensitive reason rather
      // than comparing against the redaction placeholder.
      expect(sensitiveFindings.length).toBeGreaterThan(0);
      for (const f of sensitiveFindings) {
        expect(f.status).toBe('INCONCLUSIVE');
        // Guard against the regression where rules compare against the
        // literal placeholder string and fail.
        expect(f.description).not.toMatch(/\(sensitive value\)/);
      }

      // No bucket-scoped FAIL should be produced from the redacted value.
      const bucketFails = parsed.findings.filter(
        (f: { status: string; description: string }) =>
          f.status === 'FAIL' && /\(sensitive value\)/.test(f.description),
      );
      expect(bucketFails.length).toBe(0);
    });

    it('indexed-addresses: module/resource indices like [0] and ["prod"] are normalised and the plan-buried resources are still discovered', () => {
      const result = runCli(
        `${planDir}/indexed-addresses --plan ${planDir}/indexed-addresses/plan.json --format json`,
      );
      const parsed = JSON.parse(result.stdout);

      const bedrock = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(bedrock?.status).toBe('PASS');
      // Citation preserves the full indexed plan address
      expect(bedrock?.filePath).toMatch(
        /^plan:module\.bedrock_governance\[0\]\.aws_bedrock_model_invocation_logging_configuration/,
      );

      // Supporting rules (versioning / encryption / lifecycle / retention) all
      // matched their indexed addresses too and should PASS.
      const vers = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.x.1');
      expect(vers?.status).toBe('PASS');
      const enc = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.x.2a');
      expect(enc?.status).toBe('PASS');
      const lc = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.1.2b');
      expect(lc?.status).toBe('PASS');
      const cw = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.1.2a');
      expect(cw?.status).toBe('PASS');

      expect(result.exitCode).toBe(0);
    });
  });

  describe('S-9.x.3 hard-rails body inspection', () => {
    const grDir = path.resolve(__dirname, '../fixtures/guardrail-bodies');

    function hardRails(fixture: string, args = ''): Array<{ status: string; description: string }> {
      const result = runCli(`${grDir}/${fixture} ${args} --format json`.trim());
      const parsed = JSON.parse(result.stdout);
      return parsed.findings.filter((f: { ruleId: string }) => f.ruleId === 'S-9.x.3');
    }

    it('empty-body → WARN (empty)', () => {
      const [f] = hardRails('empty-body');
      expect(f.status).toBe('WARN');
      expect(f.description).toMatch(/no policy body/);
    });

    it('all-none → WARN', () => {
      const [f] = hardRails('all-none');
      expect(f.status).toBe('WARN');
    });

    it('both-mandatory-blocking → PASS', () => {
      const [f] = hardRails('both-mandatory-blocking');
      expect(f.status).toBe('PASS');
    });

    it('content-only-no-prompt-attack → WARN naming prompt injection', () => {
      const [f] = hardRails('content-only-no-prompt-attack');
      expect(f.status).toBe('WARN');
      expect(f.description).toMatch(/prompt injection/);
    });

    it('prompt-attack-only-no-content → WARN naming the content gap', () => {
      const [f] = hardRails('prompt-attack-only-no-content');
      expect(f.status).toBe('WARN');
      expect(f.description).toMatch(/harmful-content filter/);
    });

    it('pii-anonymize → PASS (ANONYMIZE counts as enforcing)', () => {
      const [f] = hardRails('pii-anonymize');
      expect(f.status).toBe('PASS');
      expect(f.description).toMatch(/Also enforcing: PII/);
    });

    it('grounding-threshold-set → PASS with grounding enforcing', () => {
      const [f] = hardRails('grounding-threshold-set');
      expect(f.status).toBe('PASS');
      expect(f.description).toMatch(/contextual grounding/);
    });

    it('dynamic-filters → INCONCLUSIVE', () => {
      const [f] = hardRails('dynamic-filters');
      expect(f.status).toBe('INCONCLUSIVE');
    });

    it('mixed-surfaces → one finding per guardrail; strong PASS names the attaching agent, weak WARN', () => {
      const findings = hardRails('mixed-surfaces');
      expect(findings).toHaveLength(2);
      const strong = findings.find((f) => f.description.includes('aws_bedrock_guardrail.strong'))!;
      const weak = findings.find((f) => f.description.includes('aws_bedrock_guardrail.weak'))!;
      expect(strong.status).toBe('PASS');
      expect(strong.description).toMatch(/attached to agent\(s\): support_bot/);
      expect(strong.description).toMatch(/denied topic/);
      expect(weak.status).toBe('WARN');
    });
  });

  describe('INCONCLUSIVE behaviour', () => {
    const inconclusiveDir = path.resolve(__dirname, '../fixtures/inconclusive');

    it('SSM-sourced bucket name produces INCONCLUSIVE findings (exit 1 in default strict mode)', () => {
      const result = runCli(`${inconclusiveDir}/ssm-bucket --format json`);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBeGreaterThan(0);
      const inconclusive = parsed.findings.filter(
        (f: { status: string }) => f.status === 'INCONCLUSIVE',
      );
      expect(inconclusive.length).toBeGreaterThan(0);
      // every inconclusive should mention the SSM expression
      for (const f of inconclusive) {
        expect(f.description).toMatch(/data\.aws_ssm_parameter|SSM/);
      }
    });

    it('SSM-sourced bucket name with --no-strict exits 0 even with INCONCLUSIVE', () => {
      const result = runCli(`${inconclusiveDir}/ssm-bucket --no-strict --format json`);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBeGreaterThan(0);
      // No FAIL/WARN should be present (only INCONCLUSIVE for the bucket-scoped rules)
      expect(parsed.summary.fail).toBe(0);
      expect(parsed.summary.warn).toBe(0);
    });

    it('var without default produces INCONCLUSIVE (exit 1 default)', () => {
      const result = runCli(`${inconclusiveDir}/var-no-default --format json`);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBeGreaterThan(0);
      const inconclusive = parsed.findings.filter(
        (f: { status: string }) => f.status === 'INCONCLUSIVE',
      );
      for (const f of inconclusive) {
        expect(f.description).toMatch(/var\.log_bucket_name|var\.log_group_name/);
      }
    });

    it('var with default resolves and exits 0 (fully compliant)', () => {
      const result = runCli(`${inconclusiveDir}/var-with-default --format json`);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBe(0);
      expect(parsed.summary.fail).toBe(0);
      expect(parsed.summary.warn).toBe(0);
      expect(parsed.summary.pass).toBeGreaterThan(0);
    });
  });
});
