import { describe, it, expect } from 'vitest';
import { resolveExpression, resolveOrPlanFallback, resolveScalarReference } from '../../src/resolver';
import {
  ParsedFile,
  HCL2JSONOutput,
  PlanOverlay,
  PlanResource,
} from '../../src/types';

function file(json: HCL2JSONOutput): ParsedFile {
  return { filePath: 'test.tf', json, rawHcl: '' };
}

function makeOverlay(opts: {
  variables?: Record<string, string | number | boolean>;
  resources?: Array<Partial<PlanResource> & { key: string }>;
  // Optional: multiple instances under the same normalised key for
  // count/for_each divergence tests. The `key` is the normalised name; entries
  // become a PlanResource[] under `instancesByNormalised[key]`.
  instanceGroups?: Array<{
    key: string;
    instances: Array<Partial<PlanResource> & { address: string }>;
  }>;
  outputs?: Record<string, { value: string | number | boolean; sensitive?: boolean }>;
}): PlanOverlay {
  const resources = new Map<string, PlanResource>();
  const instancesByNormalised = new Map<string, PlanResource[]>();
  for (const r of opts.resources ?? []) {
    const pr: PlanResource = {
      address: r.address ?? r.key,
      type: r.type ?? r.key.split('.')[0],
      name: r.name ?? r.key.split('.').slice(1).join('.'),
      values: r.values ?? {},
      unknownPaths: r.unknownPaths ?? new Set(),
      sensitivePaths: r.sensitivePaths ?? new Set(),
    };
    resources.set(r.key, pr);
    instancesByNormalised.set(r.key, [pr]);
  }
  for (const group of opts.instanceGroups ?? []) {
    const list: PlanResource[] = group.instances.map((i) => ({
      address: i.address,
      type: i.type ?? group.key.split('.')[0],
      name: i.name ?? group.key.split('.').slice(1).join('.'),
      values: i.values ?? {},
      unknownPaths: i.unknownPaths ?? new Set(),
      sensitivePaths: i.sensitivePaths ?? new Set(),
    }));
    instancesByNormalised.set(group.key, list);
    if (!resources.has(group.key) && list.length > 0) {
      resources.set(group.key, list[0]);
    }
  }
  return {
    formatVersion: '1.2',
    terraformVersion: '1.7.5',
    resources,
    instancesByNormalised,
    deletions: new Map(),
    flags: { noActionableChanges: false },
    variables: new Map(Object.entries(opts.variables ?? {})),
    outputs: new Map(
      Object.entries(opts.outputs ?? {}).map(([k, v]) => [
        k,
        { value: v.value, sensitive: v.sensitive === true },
      ]),
    ),
  };
}

describe('resolveExpression', () => {
  describe('literals', () => {
    it('returns literal for a plain string', () => {
      const result = resolveExpression('my-bucket-name', []);
      expect(result).toEqual({ kind: 'literal', value: 'my-bucket-name' });
    });

    it('returns undefined for non-string input', () => {
      expect(resolveExpression(123, [])).toBeUndefined();
      expect(resolveExpression(undefined, [])).toBeUndefined();
      expect(resolveExpression(null, [])).toBeUndefined();
    });
  });

  describe('aws_* resource references', () => {
    it('resolves aws_s3_bucket.<name>.id to the literal bucket name', () => {
      const files = [
        file({ resource: { aws_s3_bucket: { logs: [{ bucket: 'real-bucket' }] } } }),
      ];
      const result = resolveExpression('${aws_s3_bucket.logs.id}', files);
      expect(result).toEqual({ kind: 'literal', value: 'real-bucket' });
    });

    it('returns address when aws_s3_bucket.bucket attribute uses interpolation', () => {
      const files = [
        file({
          resource: { aws_s3_bucket: { logs: [{ bucket: '${var.env}-logs' }] } },
        }),
      ];
      const result = resolveExpression('${aws_s3_bucket.logs.id}', files);
      expect(result).toEqual({
        kind: 'address',
        value: 'aws_s3_bucket.logs',
        resourceType: 'aws_s3_bucket',
        resourceName: 'logs',
      });
    });

    it('returns address when aws_s3_bucket resource is not in scanned files', () => {
      const result = resolveExpression('${aws_s3_bucket.external.id}', []);
      expect(result).toMatchObject({ kind: 'address', value: 'aws_s3_bucket.external' });
    });

    it('handles bare ref without interpolation braces', () => {
      const files = [
        file({ resource: { aws_s3_bucket: { logs: [{ bucket: 'real-bucket' }] } } }),
      ];
      const result = resolveExpression('aws_s3_bucket.logs.id', files);
      expect(result).toEqual({ kind: 'literal', value: 'real-bucket' });
    });

    it('resolves resource names containing uppercase letters and hyphens', () => {
      const files = [
        file({ resource: { aws_s3_bucket: { MyBucket: [{ bucket: 'mixed-case-bucket' }] } } }),
        file({ resource: { aws_s3_bucket: { 'prod-logs': [{ bucket: 'hyphen-bucket' }] } } }),
      ];
      expect(resolveExpression('${aws_s3_bucket.MyBucket.id}', files)).toEqual({
        kind: 'literal',
        value: 'mixed-case-bucket',
      });
      expect(resolveExpression('${aws_s3_bucket.prod-logs.id}', files)).toEqual({
        kind: 'literal',
        value: 'hyphen-bucket',
      });
    });
  });

  describe('Terraform variables', () => {
    it('resolves var.X to its literal default', () => {
      const files = [
        file({ variable: { log_bucket: [{ default: 'default-bucket' }] } }),
      ];
      const result = resolveExpression('${var.log_bucket}', files);
      expect(result).toEqual({ kind: 'literal', value: 'default-bucket' });
    });

    it('returns var-no-default when default is absent', () => {
      const files = [file({ variable: { log_bucket: [{ type: 'string' }] } })];
      const result = resolveExpression('${var.log_bucket}', files, 'logging_config.s3_config.bucket_name');
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'var-no-default',
        expression: '${var.log_bucket}',
        sourceField: 'logging_config.s3_config.bucket_name',
      });
    });

    it('returns var-no-default when variable is not declared in scanned files', () => {
      const result = resolveExpression('${var.unknown}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'var-no-default' });
    });

    it('does not resolve when default is itself an interpolation', () => {
      const files = [
        file({ variable: { log_bucket: [{ default: '${var.env}-logs' }] } }),
      ];
      const result = resolveExpression('${var.log_bucket}', files);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'var-no-default' });
    });
  });

  describe('Terraform locals', () => {
    it('resolves local.X to its literal value', () => {
      const files = [file({ locals: [{ log_bucket: 'local-bucket' }] })];
      const result = resolveExpression('${local.log_bucket}', files);
      expect(result).toEqual({ kind: 'literal', value: 'local-bucket' });
    });

    it('returns local-not-literal when local is not a literal string', () => {
      const files = [file({ locals: [{ log_bucket: '${var.env}-logs' }] })];
      const result = resolveExpression('${local.log_bucket}', files);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'local-not-literal' });
    });

    it('returns local-not-literal when local is not declared', () => {
      const result = resolveExpression('${local.missing}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'local-not-literal' });
    });
  });

  describe('data sources', () => {
    it('classifies data.aws_ssm_parameter.X.value as data-source-ssm', () => {
      const result = resolveExpression(
        '${data.aws_ssm_parameter.log_bucket.value}',
        [],
        'logging_config.s3_config.bucket_name',
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'data-source-ssm',
        expression: '${data.aws_ssm_parameter.log_bucket.value}',
      });
    });

    it('classifies other data sources as data-source-other', () => {
      const result = resolveExpression('${data.aws_caller_identity.current.account_id}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'data-source-other' });
    });
  });

  describe('module outputs', () => {
    it('classifies module.X.Y as module-output when no overlay is present', () => {
      const result = resolveExpression('${module.logging.bucket_name}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'module-output' });
    });

    it('promotes module.X.Y to literal when overlay carries the output value', () => {
      const overlay = makeOverlay({
        outputs: { 'module.logging.bucket_name': { value: 'co-access-logs' } },
      });
      const result = resolveExpression(
        '${module.logging.bucket_name}',
        [],
        'target_bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'co-access-logs' });
    });

    it('strips [...] index segments so count/for_each module refs resolve', () => {
      const overlay = makeOverlay({
        outputs: { 'module.logging.bucket_name': { value: 'co-access-logs' } },
      });
      const result = resolveExpression(
        '${module.logging[0].bucket_name}',
        [],
        'target_bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'co-access-logs' });
    });

    it('resolves nested module references (module.outer.module.inner.X)', () => {
      const overlay = makeOverlay({
        outputs: { 'module.outer.module.inner.bucket_name': { value: 'nested-bucket' } },
      });
      const result = resolveExpression(
        '${module.outer.module.inner.bucket_name}',
        [],
        'target_bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'nested-bucket' });
    });

    it('returns plan-sensitive-redacted when the output is sensitive', () => {
      const overlay = makeOverlay({
        outputs: {
          'module.logging.bucket_name': { value: 'co-access-logs', sensitive: true },
        },
      });
      const result = resolveExpression(
        '${module.logging.bucket_name}',
        [],
        'target_bucket',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-sensitive-redacted',
      });
    });

    it('falls back to module-output when the overlay has no matching entry', () => {
      const overlay = makeOverlay({
        outputs: { 'module.other.foo': { value: 'x' } },
      });
      const result = resolveExpression(
        '${module.logging.bucket_name}',
        [],
        'target_bucket',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'module-output' });
    });
  });

  describe('complex interpolations', () => {
    it('classifies prefix-${var.X} as complex-interpolation', () => {
      const result = resolveExpression('logs-${var.env}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'complex-interpolation' });
    });

    it('classifies ${var.a}-${var.b} as complex-interpolation', () => {
      const result = resolveExpression('${var.env}-${var.suffix}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'complex-interpolation' });
    });
  });

  describe('module-scoped variable resolution', () => {
    it('resolves var.X only from files in the same directory as sourceFilePath', () => {
      const parentFile: ParsedFile = {
        filePath: '/project/root.tf',
        json: { variable: { log_bucket: [{ default: 'parent-default' }] } },
        rawHcl: '',
      };
      const childFile: ParsedFile = {
        filePath: '/project/modules/bedrock/main.tf',
        json: { variable: { log_bucket: [{ type: 'string' }] } },
        rawHcl: '',
      };

      // Without sourceFilePath: leaks parent default into child context (old behaviour)
      const leaked = resolveExpression('${var.log_bucket}', [parentFile, childFile]);
      expect(leaked).toEqual({ kind: 'literal', value: 'parent-default' });

      // With sourceFilePath scoped to child dir: child has no default → INCONCLUSIVE
      const scoped = resolveExpression(
        '${var.log_bucket}',
        [parentFile, childFile],
        'logging_config.s3_config.bucket_name',
        '/project/modules/bedrock/main.tf',
      );
      expect(scoped).toMatchObject({ kind: 'unresolvable', reason: 'var-no-default' });
    });

    it('resolves var.X from correct module when same-dir file has a default', () => {
      const childFile: ParsedFile = {
        filePath: '/project/modules/bedrock/main.tf',
        json: { variable: { log_bucket: [{ default: 'child-bucket' }] } },
        rawHcl: '',
      };
      const result = resolveExpression(
        '${var.log_bucket}',
        [childFile],
        'field',
        '/project/modules/bedrock/main.tf',
      );
      expect(result).toEqual({ kind: 'literal', value: 'child-bucket' });
    });

    it('resolves local.X only from files in the same directory as sourceFilePath', () => {
      const parentFile: ParsedFile = {
        filePath: '/project/root.tf',
        json: { locals: [{ log_bucket: 'parent-local-bucket' }] },
        rawHcl: '',
      };
      const childFile: ParsedFile = {
        filePath: '/project/modules/bedrock/main.tf',
        json: { locals: [] },
        rawHcl: '',
      };

      // Scoped to child dir: child has no matching local → unresolvable
      const result = resolveExpression(
        '${local.log_bucket}',
        [parentFile, childFile],
        'field',
        '/project/modules/bedrock/main.tf',
      );
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'local-not-literal' });
    });
  });

  describe('plan overlay resolution', () => {
    it('resolves var.X from overlay.variables when no HCL default exists', () => {
      const files = [file({ variable: { log_bucket: [{ type: 'string' }] } })];
      const overlay = makeOverlay({ variables: { log_bucket: 'overlay-bucket' } });
      const result = resolveExpression(
        '${var.log_bucket}',
        files,
        'logging_config.s3_config.bucket_name',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'overlay-bucket' });
    });

    it('prefers overlay value over HCL default for var.X', () => {
      const files = [file({ variable: { env: [{ default: 'dev' }] } })];
      const overlay = makeOverlay({ variables: { env: 'prod' } });
      const result = resolveExpression('${var.env}', files, 'f', undefined, overlay);
      expect(result).toEqual({ kind: 'literal', value: 'prod' });
    });

    it('resolves aws_<type>.<name>.<attr> from overlay.resources', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_s3_bucket.logs',
            values: { bucket: 'overlay-bucket-name' },
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.bucket}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'overlay-bucket-name' });
    });

    it('returns plan-known-after-apply when attribute is in unknownPaths', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_s3_bucket.logs',
            values: { bucket: null },
            unknownPaths: new Set(['bucket']),
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.bucket}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-known-after-apply',
      });
    });

    it('anchors on the HCL resource address when the value is after_unknown but the resource IS declared in scanned HCL', () => {
      // The bucket name is computed-at-apply, but the resource is on disk: the
      // reference still names a specific resource, so we return its address for
      // downstream identity matching rather than degrading to INCONCLUSIVE.
      // (The test above uses files: [] - resource not on disk - and correctly
      // stays plan-known-after-apply: there is no accurate HCL to anchor on.)
      const files = [
        file({ resource: { aws_s3_bucket: { logs: [{ bucket: '${var.env}-logs' }] } } }),
      ];
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_s3_bucket.logs',
            values: { bucket: null },
            unknownPaths: new Set(['bucket']),
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.bucket}',
        files,
        'f',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({ kind: 'address', value: 'aws_s3_bucket.logs' });
    });

    it('returns plan-sensitive-redacted when attribute is in sensitivePaths', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_s3_bucket.logs',
            values: { bucket: 'real-but-hidden' },
            sensitivePaths: new Set(['bucket']),
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.bucket}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-sensitive-redacted',
      });
    });

    it('returns plan-sensitive-redacted when value reads "(sensitive value)"', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_s3_bucket.logs',
            values: { bucket: '(sensitive value)' },
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.bucket}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-sensitive-redacted',
      });
    });

    it('resolves data.<type>.<name>.<attr> from overlay when present', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'data.aws_ssm_parameter.x',
            type: 'aws_ssm_parameter',
            values: { value: 'ssm-result' },
          },
        ],
      });
      const result = resolveExpression(
        '${data.aws_ssm_parameter.x.value}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'ssm-result' });
    });

    it('leaves data sources unresolvable when overlay has no entry', () => {
      const overlay = makeOverlay({});
      const result = resolveExpression(
        '${data.aws_ssm_parameter.x.value}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'data-source-ssm',
      });
    });

    it('normalises indexed addresses on lookup', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_s3_bucket.logs',
            values: { bucket: 'real-bucket' },
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs[0].bucket}',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'real-bucket' });
    });

    it('static AWS_RES_REF accepts indexed addresses (regex update)', () => {
      const files = [
        file({ resource: { aws_s3_bucket: { logs: [{ bucket: 'real-bucket' }] } } }),
      ];
      const result = resolveExpression('${aws_s3_bucket.logs[0].id}', files);
      expect(result).toEqual({ kind: 'literal', value: 'real-bucket' });
    });

    it('returns a literal when every instance under a count/for_each agrees on the attribute', () => {
      const overlay = makeOverlay({
        instanceGroups: [
          {
            key: 'aws_s3_bucket.logs',
            instances: [
              {
                address: 'aws_s3_bucket.logs[0]',
                type: 'aws_s3_bucket',
                name: 'logs',
                values: { bucket: 'shared-name' },
              },
              {
                address: 'aws_s3_bucket.logs[1]',
                type: 'aws_s3_bucket',
                name: 'logs',
                values: { bucket: 'shared-name' },
              },
            ],
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.id}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'shared-name' });
    });

    it('returns plan-instances-divergent when instances disagree on the attribute', () => {
      const overlay = makeOverlay({
        instanceGroups: [
          {
            key: 'aws_s3_bucket.logs',
            instances: [
              {
                address: 'aws_s3_bucket.logs[0]',
                type: 'aws_s3_bucket',
                name: 'logs',
                values: { bucket: 'prod-logs' },
              },
              {
                address: 'aws_s3_bucket.logs[1]',
                type: 'aws_s3_bucket',
                name: 'logs',
                values: { bucket: 'dev-logs-unencrypted' },
              },
            ],
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.id}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({
        kind: 'unresolvable',
        expression: '${aws_s3_bucket.logs.id}',
        reason: 'plan-instances-divergent',
        sourceField: 'bucket',
      });
    });

    it('any-instance-unknown wins over a concrete value in a sibling instance', () => {
      const overlay = makeOverlay({
        instanceGroups: [
          {
            key: 'aws_s3_bucket.logs',
            instances: [
              {
                address: 'aws_s3_bucket.logs[0]',
                type: 'aws_s3_bucket',
                name: 'logs',
                values: { bucket: 'known-name' },
              },
              {
                address: 'aws_s3_bucket.logs[1]',
                type: 'aws_s3_bucket',
                name: 'logs',
                values: { bucket: null },
                unknownPaths: new Set(['bucket']),
              },
            ],
          },
        ],
      });
      const result = resolveExpression(
        '${aws_s3_bucket.logs.id}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({
        kind: 'unresolvable',
        expression: '${aws_s3_bucket.logs.id}',
        reason: 'plan-known-after-apply',
        sourceField: 'bucket',
      });
    });
  });

  describe('terraform_remote_state references', () => {
    it('resolves outputs.<key> to a literal when overlay contains the value', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'data.terraform_remote_state.account_baseline',
            type: 'terraform_remote_state',
            values: { outputs: { log_bucket: 'central-logs-bucket' } },
          },
        ],
      });
      const result = resolveExpression(
        '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'central-logs-bucket' });
    });

    it('returns plan-remote-state-unreachable when the data source is absent from the overlay', () => {
      const overlay = makeOverlay({ resources: [] });
      const result = resolveExpression(
        '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-remote-state-unreachable',
      });
    });

    it('honours unknownPaths for the specific output', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'data.terraform_remote_state.audit',
            type: 'terraform_remote_state',
            values: { outputs: {} },
            unknownPaths: new Set(['outputs.log_bucket']),
          },
        ],
      });
      const result = resolveExpression(
        '${data.terraform_remote_state.audit.outputs.log_bucket}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-known-after-apply',
      });
    });

    it('honours sensitivePaths for the specific output', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'data.terraform_remote_state.security',
            type: 'terraform_remote_state',
            values: { outputs: { api_key: 'secret' } },
            sensitivePaths: new Set(['outputs.api_key']),
          },
        ],
      });
      const result = resolveExpression(
        '${data.terraform_remote_state.security.outputs.api_key}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-sensitive-redacted',
      });
    });

    it('treats the literal "(sensitive value)" string as sensitive', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'data.terraform_remote_state.security',
            type: 'terraform_remote_state',
            values: { outputs: { api_key: '(sensitive value)' } },
          },
        ],
      });
      const result = resolveExpression(
        '${data.terraform_remote_state.security.outputs.api_key}',
        [],
        'bucket',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-sensitive-redacted',
      });
    });

    it('returns data-source-other when no overlay is provided (static-only scan)', () => {
      const result = resolveExpression(
        '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
        [],
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'data-source-other',
      });
    });
  });

  describe('resolveOrPlanFallback', () => {
    it('falls back to overlay-resolved attribute when expression is complex', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_bedrock_model_invocation_logging_configuration.main',
            values: {
              logging_config: {
                s3_config: { bucket_name: 'final-bucket-name' },
              },
            },
          },
        ],
      });
      const result = resolveOrPlanFallback(
        '${local.prefix}-${var.env}-logs',
        'aws_bedrock_model_invocation_logging_configuration.main',
        'logging_config.s3_config.bucket_name',
        [],
        'logging_config.s3_config.bucket_name',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'final-bucket-name' });
    });

    it('returns the original unresolvable when no overlay is provided', () => {
      const result = resolveOrPlanFallback(
        '${local.prefix}-${var.env}-logs',
        'aws_bedrock_model_invocation_logging_configuration.main',
        'logging_config.s3_config.bucket_name',
        [],
        'f',
        undefined,
        undefined,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'complex-interpolation',
      });
    });

    it('falls back to plan-known-after-apply when overlay path is unknown', () => {
      const overlay = makeOverlay({
        resources: [
          {
            key: 'aws_bedrock_model_invocation_logging_configuration.main',
            values: { logging_config: { s3_config: { bucket_name: null } } },
            unknownPaths: new Set(['logging_config.s3_config.bucket_name']),
          },
        ],
      });
      const result = resolveOrPlanFallback(
        '${local.prefix}-${var.env}-logs',
        'aws_bedrock_model_invocation_logging_configuration.main',
        'logging_config.s3_config.bucket_name',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'plan-known-after-apply',
      });
    });

    it('passes through PASS results unchanged', () => {
      const overlay = makeOverlay({ variables: { env: 'prod' } });
      const result = resolveOrPlanFallback(
        '${var.env}',
        'unused',
        'unused',
        [],
        'f',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'prod' });
    });
  });

  describe('resolveScalarReference with overlay', () => {
    it('resolves var.X from overlay for numeric/boolean variables', () => {
      const overlay = makeOverlay({ variables: { log_retention_days: 365 } });
      const result = resolveScalarReference(
        '${var.log_retention_days}',
        [],
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 365 });
    });

    it('resolves var.config.field from a flattened overlay key', () => {
      const overlay = makeOverlay({
        variables: { 'bedrock_logging.text_enabled': true },
      });
      const result = resolveScalarReference(
        '${var.bedrock_logging.text_enabled}',
        [],
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: true });
    });
  });

  describe('object/list variable paths', () => {
    it('resolves var.config.field from overlay flattened keys', () => {
      const overlay = makeOverlay({
        variables: { 'bedrock_logging.bucket_name': 'acme-bedrock-logs' },
      });
      const result = resolveExpression(
        '${var.bedrock_logging.bucket_name}',
        [],
        'logging_config.s3_config.bucket_name',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'acme-bedrock-logs' });
    });

    it('resolves var.list[N] from overlay flattened keys', () => {
      const overlay = makeOverlay({
        variables: { 'zones[0]': 'us-east-1a' },
      });
      const result = resolveExpression(
        '${var.zones[0]}',
        [],
        'availability_zone',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'us-east-1a' });
    });

    it('resolves var.config.field from a static object default', () => {
      const files = [
        file({
          variable: {
            bedrock_logging: [
              { default: { bucket_name: 'default-bucket', text_enabled: true } },
            ],
          },
        }),
      ];
      const result = resolveExpression('${var.bedrock_logging.bucket_name}', files);
      expect(result).toEqual({ kind: 'literal', value: 'default-bucket' });
    });

    it('resolves var.list[N] from a static list default', () => {
      const files = [
        file({
          variable: {
            zones: [{ default: ['us-east-1a', 'us-east-1b'] }],
          },
        }),
      ];
      const result = resolveExpression('${var.zones[1]}', files);
      expect(result).toEqual({ kind: 'literal', value: 'us-east-1b' });
    });

    it('returns var-no-default when dotted path misses both overlay and default', () => {
      const files = [
        file({ variable: { bedrock_logging: [{ default: { other_field: 'x' } }] } }),
      ];
      const result = resolveExpression(
        '${var.bedrock_logging.bucket_name}',
        files,
        'logging_config.s3_config.bucket_name',
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'var-no-default',
      });
    });

    it('overlay flattened value beats static default at the same path', () => {
      const files = [
        file({
          variable: {
            bedrock_logging: [
              { default: { bucket_name: 'default-bucket' } },
            ],
          },
        }),
      ];
      const overlay = makeOverlay({
        variables: { 'bedrock_logging.bucket_name': 'overlay-bucket' },
      });
      const result = resolveExpression(
        '${var.bedrock_logging.bucket_name}',
        files,
        'f',
        undefined,
        overlay,
      );
      expect(result).toEqual({ kind: 'literal', value: 'overlay-bucket' });
    });

    it('resolveScalarReference unwraps boolean from a static object default', () => {
      const files = [
        file({
          variable: {
            bedrock_logging: [
              { default: { text_enabled: true, image_enabled: false } },
            ],
          },
        }),
      ];
      expect(resolveScalarReference('${var.bedrock_logging.text_enabled}', files)).toEqual({
        kind: 'literal',
        value: true,
      });
      expect(resolveScalarReference('${var.bedrock_logging.image_enabled}', files)).toEqual({
        kind: 'literal',
        value: false,
      });
    });
  });

  describe('source field tracking', () => {
    it('preserves sourceField in unresolvable results', () => {
      const result = resolveExpression(
        '${var.bucket}',
        [],
        'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      );
      expect(result).toMatchObject({
        sourceField: 'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      });
    });
  });
});
