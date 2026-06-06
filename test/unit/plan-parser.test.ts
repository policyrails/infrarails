import { describe, it, expect } from 'vitest';
import { parsePlanObject, normaliseAddress } from '../../src/plan-parser';

describe('normaliseAddress', () => {
  it('strips bracketed indices', () => {
    expect(normaliseAddress('aws_s3_bucket.logs[0]')).toBe('aws_s3_bucket.logs');
    expect(normaliseAddress('aws_s3_bucket.logs["prod"]')).toBe('aws_s3_bucket.logs');
  });

  it('strips leading module prefixes', () => {
    expect(normaliseAddress('module.foo.aws_s3_bucket.logs')).toBe('aws_s3_bucket.logs');
    expect(normaliseAddress('module.foo.module.bar.aws_s3_bucket.logs')).toBe(
      'aws_s3_bucket.logs',
    );
  });

  it('strips indexed modules and indexed resources together', () => {
    expect(normaliseAddress('module.foo[0].aws_s3_bucket.logs[0]')).toBe(
      'aws_s3_bucket.logs',
    );
  });

  it('leaves a plain address untouched', () => {
    expect(normaliseAddress('aws_s3_bucket.logs')).toBe('aws_s3_bucket.logs');
  });
});

describe('parsePlanObject - format validation', () => {
  it('rejects a non-object top level', () => {
    expect(() => parsePlanObject('not an object' as unknown)).toThrow(/top level/);
  });

  it('rejects a plan missing format_version', () => {
    expect(() => parsePlanObject({ terraform_version: '1.7.5' })).toThrow(
      /format_version/,
    );
  });

  it('rejects an unsupported major version', () => {
    expect(() =>
      parsePlanObject({ format_version: '2.0', terraform_version: '2.0' }),
    ).toThrow(/Unsupported plan format/);
  });

  it('rejects errored:true plans', () => {
    expect(() =>
      parsePlanObject({
        format_version: '1.2',
        terraform_version: '1.7.5',
        errored: true,
      }),
    ).toThrow(/errored state/);
  });

  it('parses a minimal valid plan with no resources', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
    });
    expect(overlay.formatVersion).toBe('1.2');
    expect(overlay.terraformVersion).toBe('1.7.5');
    expect(overlay.resources.size).toBe(0);
    expect(overlay.deletions.size).toBe(0);
    expect(overlay.variables.size).toBe(0);
    expect(overlay.flags).toEqual({ noActionableChanges: false });
  });
});

describe('parsePlanObject - root resources', () => {
  it('parses root_module.resources into the overlay map keyed by type.name', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          resources: [
            {
              address: 'aws_s3_bucket.logs',
              type: 'aws_s3_bucket',
              name: 'logs',
              values: { bucket: 'acme-logs' },
            },
          ],
        },
      },
    });
    const entry = overlay.resources.get('aws_s3_bucket.logs');
    expect(entry).toBeDefined();
    expect(entry!.values.bucket).toBe('acme-logs');
    expect(entry!.unknownPaths.size).toBe(0);
    expect(entry!.sensitivePaths.size).toBe(0);
  });

  it('captures variable values', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      variables: {
        log_retention_days: { value: 365 },
        env: { value: 'prod' },
        enabled: { value: true },
      },
    });
    expect(overlay.variables.get('log_retention_days')).toBe(365);
    expect(overlay.variables.get('env')).toBe('prod');
    expect(overlay.variables.get('enabled')).toBe(true);
  });

  it('flattens object variables into dotted scalar keys', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      variables: {
        bedrock_logging: {
          value: {
            bucket_name: 'acme-bedrock-logs',
            text_enabled: true,
            image_enabled: false,
            retention_days: 365,
          },
        },
      },
    });
    expect(overlay.variables.get('bedrock_logging.bucket_name')).toBe('acme-bedrock-logs');
    expect(overlay.variables.get('bedrock_logging.text_enabled')).toBe(true);
    expect(overlay.variables.get('bedrock_logging.image_enabled')).toBe(false);
    expect(overlay.variables.get('bedrock_logging.retention_days')).toBe(365);
    // The bare object name is not itself stored - only its leaves.
    expect(overlay.variables.has('bedrock_logging')).toBe(false);
  });

  it('flattens nested object variables recursively', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      variables: {
        config: {
          value: {
            logging: { s3: { bucket: 'deep-bucket' } },
          },
        },
      },
    });
    expect(overlay.variables.get('config.logging.s3.bucket')).toBe('deep-bucket');
  });

  it('flattens list variables to bracket-indexed keys', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      variables: {
        zones: { value: ['us-east-1a', 'us-east-1b'] },
      },
    });
    expect(overlay.variables.get('zones[0]')).toBe('us-east-1a');
    expect(overlay.variables.get('zones[1]')).toBe('us-east-1b');
  });

  it('flattens lists of objects with index and dotted keys', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      variables: {
        endpoints: {
          value: [{ url: 'https://a', port: 443 }, { url: 'https://b', port: 8443 }],
        },
      },
    });
    expect(overlay.variables.get('endpoints[0].url')).toBe('https://a');
    expect(overlay.variables.get('endpoints[0].port')).toBe(443);
    expect(overlay.variables.get('endpoints[1].url')).toBe('https://b');
    expect(overlay.variables.get('endpoints[1].port')).toBe(8443);
  });

  it('silently drops null and non-scalar leaves', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      variables: {
        mixed: { value: { real: 'keep', missing: null, weird: undefined as unknown } },
      },
    });
    expect(overlay.variables.get('mixed.real')).toBe('keep');
    expect(overlay.variables.has('mixed.missing')).toBe(false);
    expect(overlay.variables.has('mixed.weird')).toBe(false);
  });
});

describe('parsePlanObject - nested modules', () => {
  it('walks child_modules recursively and surfaces module-buried resources', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          resources: [],
          child_modules: [
            {
              address: 'module.logging',
              resources: [
                {
                  address: 'module.logging.aws_cloudwatch_log_group.this',
                  type: 'aws_cloudwatch_log_group',
                  name: 'this',
                  values: { name: 'bedrock-logs', retention_in_days: 365 },
                },
              ],
              child_modules: [
                {
                  address: 'module.logging.module.inner',
                  resources: [
                    {
                      address:
                        'module.logging.module.inner.aws_s3_bucket.deep',
                      type: 'aws_s3_bucket',
                      name: 'deep',
                      values: { bucket: 'deep-bucket' },
                    },
                  ],
                },
              ],
            },
          ],
        },
      },
    });
    const lg = overlay.resources.get('aws_cloudwatch_log_group.this');
    expect(lg).toBeDefined();
    expect(lg!.address).toBe('module.logging.aws_cloudwatch_log_group.this');
    expect(lg!.values.retention_in_days).toBe(365);

    const deep = overlay.resources.get('aws_s3_bucket.deep');
    expect(deep).toBeDefined();
    expect(deep!.address).toBe(
      'module.logging.module.inner.aws_s3_bucket.deep',
    );
  });
});

describe('parsePlanObject - after_unknown / after_sensitive flattening', () => {
  it('flattens after_unknown to dotted paths on the matching resource', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          resources: [
            {
              address: 'aws_s3_bucket.logs',
              type: 'aws_s3_bucket',
              name: 'logs',
              values: { bucket: null },
            },
          ],
        },
      },
      resource_changes: [
        {
          address: 'aws_s3_bucket.logs',
          type: 'aws_s3_bucket',
          name: 'logs',
          change: {
            actions: ['create'],
            after_unknown: { bucket: true, arn: true, nested: { id: true } },
            after_sensitive: false,
          },
        },
      ],
    });
    const res = overlay.resources.get('aws_s3_bucket.logs');
    expect(res!.unknownPaths.has('bucket')).toBe(true);
    expect(res!.unknownPaths.has('arn')).toBe(true);
    expect(res!.unknownPaths.has('nested.id')).toBe(true);
    expect(res!.sensitivePaths.size).toBe(0);
  });

  it('flattens after_sensitive to dotted paths', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          resources: [
            {
              address:
                'aws_bedrock_model_invocation_logging_configuration.main',
              type: 'aws_bedrock_model_invocation_logging_configuration',
              name: 'main',
              values: {
                logging_config: { s3_config: { bucket_name: '(sensitive value)' } },
              },
            },
          ],
        },
      },
      resource_changes: [
        {
          address: 'aws_bedrock_model_invocation_logging_configuration.main',
          type: 'aws_bedrock_model_invocation_logging_configuration',
          name: 'main',
          change: {
            actions: ['create'],
            after_unknown: false,
            after_sensitive: {
              logging_config: { s3_config: { bucket_name: true } },
            },
          },
        },
      ],
    });
    const res = overlay.resources.get(
      'aws_bedrock_model_invocation_logging_configuration.main',
    );
    expect(
      res!.sensitivePaths.has('logging_config.s3_config.bucket_name'),
    ).toBe(true);
  });
});

describe('parsePlanObject - deletions and replacements', () => {
  it('extracts delete actions into the deletions map with before values', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: { root_module: { resources: [] } },
      resource_changes: [
        {
          address: 'aws_bedrock_model_invocation_logging_configuration.main',
          type: 'aws_bedrock_model_invocation_logging_configuration',
          name: 'main',
          change: {
            actions: ['delete'],
            before: {
              logging_config: {
                s3_config: { bucket_name: 'acme-prod-bedrock-logs' },
              },
            },
          },
        },
      ],
    });
    const d = overlay.deletions.get(
      'aws_bedrock_model_invocation_logging_configuration.main',
    );
    expect(d).toBeDefined();
    expect(d!.replaceWithCreate).toBe(false);
    expect(d!.before).toBeDefined();
  });

  it('marks replacement actions (create+delete in any order)', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: { root_module: { resources: [] } },
      resource_changes: [
        {
          address: 'aws_cloudwatch_log_group.a',
          type: 'aws_cloudwatch_log_group',
          name: 'a',
          change: { actions: ['create', 'delete'], before: { name: 'old' } },
        },
        {
          address: 'aws_cloudwatch_log_group.b',
          type: 'aws_cloudwatch_log_group',
          name: 'b',
          change: { actions: ['delete', 'create'], before: { name: 'old-b' } },
        },
      ],
    });
    expect(overlay.deletions.get('aws_cloudwatch_log_group.a')!.replaceWithCreate).toBe(
      true,
    );
    expect(overlay.deletions.get('aws_cloudwatch_log_group.b')!.replaceWithCreate).toBe(
      true,
    );
  });
});

describe('parsePlanObject - multi-instance (count / for_each)', () => {
  it('preserves every instance in instancesByNormalised while keeping a summary in resources', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          resources: [
            {
              address: 'aws_s3_bucket.logs[0]',
              type: 'aws_s3_bucket',
              name: 'logs',
              values: { bucket: 'logs-prod' },
            },
            {
              address: 'aws_s3_bucket.logs[1]',
              type: 'aws_s3_bucket',
              name: 'logs',
              values: { bucket: 'logs-dev' },
            },
          ],
        },
      },
    });
    // Legacy summary: still one entry per normalised name.
    expect(overlay.resources.size).toBe(1);
    expect(overlay.resources.get('aws_s3_bucket.logs')!.address).toBe(
      'aws_s3_bucket.logs[0]',
    );
    // Authoritative list: every instance preserved with its real address.
    const instances = overlay.instancesByNormalised.get('aws_s3_bucket.logs');
    expect(instances).toBeDefined();
    expect(instances!.length).toBe(2);
    expect(instances!.map((i) => i.address)).toEqual([
      'aws_s3_bucket.logs[0]',
      'aws_s3_bucket.logs[1]',
    ]);
    expect(instances!.map((i) => i.values.bucket)).toEqual(['logs-prod', 'logs-dev']);
  });

  it('attaches per-instance after_unknown/after_sensitive to the matching address only', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          resources: [
            {
              address: 'aws_s3_bucket.logs[0]',
              type: 'aws_s3_bucket',
              name: 'logs',
              values: { bucket: 'logs-prod' },
            },
            {
              address: 'aws_s3_bucket.logs[1]',
              type: 'aws_s3_bucket',
              name: 'logs',
              values: { bucket: null },
            },
          ],
        },
      },
      resource_changes: [
        {
          address: 'aws_s3_bucket.logs[0]',
          type: 'aws_s3_bucket',
          name: 'logs',
          change: { actions: ['create'], after_unknown: false, after_sensitive: false },
        },
        {
          address: 'aws_s3_bucket.logs[1]',
          type: 'aws_s3_bucket',
          name: 'logs',
          change: {
            actions: ['create'],
            after_unknown: { bucket: true },
            after_sensitive: false,
          },
        },
      ],
    });
    const [i0, i1] = overlay.instancesByNormalised.get('aws_s3_bucket.logs')!;
    // Instance [0] has a concrete value and no unknowns.
    expect(i0.unknownPaths.size).toBe(0);
    // Instance [1]'s unknown does NOT bleed into [0].
    expect(i1.unknownPaths.has('bucket')).toBe(true);
  });
});

describe('parsePlanObject - flags', () => {
  it('flags noActionableChanges when no actioned resources are present', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: { root_module: { resources: [] } },
      resource_changes: [
        {
          address: 'data.aws_ssm_parameter.x',
          type: 'aws_ssm_parameter',
          name: 'x',
          change: { actions: ['read'] },
        },
        {
          address: 'aws_s3_bucket.y',
          type: 'aws_s3_bucket',
          name: 'y',
          change: { actions: ['no-op'] },
        },
      ],
    });
    expect(overlay.flags.noActionableChanges).toBe(true);
  });
});

describe('parsePlanObject - child module outputs', () => {
  it('captures scalar outputs keyed by module.<path>.<name>', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.access_logs',
              outputs: {
                bucket_name: { sensitive: false, value: 'co-access-logs' },
                retention_days: { sensitive: false, value: 90 },
                enabled: { sensitive: false, value: true },
              },
            },
          ],
        },
      },
    });
    expect(overlay.outputs.get('module.access_logs.bucket_name')).toEqual({
      value: 'co-access-logs',
      sensitive: false,
    });
    expect(overlay.outputs.get('module.access_logs.retention_days')?.value).toBe(90);
    expect(overlay.outputs.get('module.access_logs.enabled')?.value).toBe(true);
  });

  it('strips [...] from indexed module addresses (count/for_each)', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.access_logs[0]',
              outputs: { bucket_name: { sensitive: false, value: 'co-access-logs' } },
            },
          ],
        },
      },
    });
    expect(overlay.outputs.get('module.access_logs.bucket_name')?.value).toBe(
      'co-access-logs',
    );
  });

  it('captures outputs from nested child modules', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.outer',
              child_modules: [
                {
                  address: 'module.outer.module.inner',
                  outputs: {
                    bucket_name: { sensitive: false, value: 'nested-bucket' },
                  },
                },
              ],
            },
          ],
        },
      },
    });
    expect(
      overlay.outputs.get('module.outer.module.inner.bucket_name')?.value,
    ).toBe('nested-bucket');
  });

  it('preserves sensitive flag and skips non-scalar values', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.shared',
              outputs: {
                token: { sensitive: true, value: 'redacted-but-present' },
                config: { sensitive: false, value: { nested: 'object' } },
                missing: { sensitive: false, value: null },
              },
            },
          ],
        },
      },
    });
    expect(overlay.outputs.get('module.shared.token')).toEqual({
      value: 'redacted-but-present',
      sensitive: true,
    });
    expect(overlay.outputs.has('module.shared.config')).toBe(false);
    expect(overlay.outputs.has('module.shared.missing')).toBe(false);
  });
});

describe('parsePlanObject - configuration reference graph', () => {
  // Mirrors the real cross-module wiring: an agent in module recruiter_api
  // attaches a guardrail declared in module bedrock_governance, plumbed through
  // module outputs and the call-site var binding.
  const planWithModuleWiring = {
    format_version: '1.2',
    terraform_version: '1.7.5',
    configuration: {
      root_module: {
        module_calls: {
          recruiter_api: {
            expressions: {
              guardrail_identifier: {
                references: [
                  'module.bedrock_governance.guardrail_identifier',
                  'module.bedrock_governance',
                ],
              },
              guardrail_version: {
                references: [
                  'module.bedrock_governance.guardrail_version',
                  'module.bedrock_governance',
                ],
              },
            },
            module: {
              resources: [
                {
                  address: 'aws_bedrockagent_agent.recruiter',
                  type: 'aws_bedrockagent_agent',
                  name: 'recruiter',
                  expressions: {
                    guardrail_configuration: {
                      references: ['var.guardrail_identifier', 'var.guardrail_version'],
                    },
                  },
                },
              ],
            },
          },
          bedrock_governance: {
            expressions: {},
            module: {
              outputs: {
                guardrail_identifier: {
                  expression: {
                    references: [
                      'aws_bedrock_guardrail.recruiter.guardrail_arn',
                      'aws_bedrock_guardrail.recruiter',
                    ],
                  },
                },
                guardrail_version: {
                  expression: {
                    references: [
                      'aws_bedrock_guardrail_version.recruiter.version',
                      'aws_bedrock_guardrail_version.recruiter',
                    ],
                  },
                },
              },
            },
          },
        },
      },
    },
  };

  it('records resource-attribute references qualified to the module scope', () => {
    const overlay = parsePlanObject(planWithModuleWiring);
    expect(overlay.configReferences).toBeDefined();
    expect(
      overlay.configReferences!.resourceAttrs.get(
        'module.recruiter_api.aws_bedrockagent_agent.recruiter#guardrail_configuration',
      ),
    ).toEqual([
      'var:module.recruiter_api::guardrail_identifier',
      'var:module.recruiter_api::guardrail_version',
    ]);
  });

  it('binds module-call inputs (var.X) to their call-site references', () => {
    const overlay = parsePlanObject(planWithModuleWiring);
    expect(
      overlay.configReferences!.varBindings.get('module.recruiter_api::guardrail_identifier'),
    ).toEqual(['out:module.bedrock_governance.guardrail_identifier']);
  });

  it('records module outputs pointing at terminal resources', () => {
    const overlay = parsePlanObject(planWithModuleWiring);
    expect(
      overlay.configReferences!.moduleOutputs.get('module.bedrock_governance.guardrail_identifier'),
    ).toEqual(['res:aws_bedrock_guardrail.recruiter']);
    expect(
      overlay.configReferences!.moduleOutputs.get('module.bedrock_governance.guardrail_version'),
    ).toEqual(['res:aws_bedrock_guardrail_version.recruiter']);
  });

  it('is undefined when the plan carries no configuration block', () => {
    const overlay = parsePlanObject({ format_version: '1.2', terraform_version: '1.7.5' });
    expect(overlay.configReferences).toBeUndefined();
  });

  it('drops references that are not resource/output/var chains (locals, data)', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      configuration: {
        root_module: {
          resources: [
            {
              address: 'aws_bedrockagent_agent.bot',
              type: 'aws_bedrockagent_agent',
              name: 'bot',
              expressions: {
                guardrail_configuration: {
                  references: ['local.gr', 'data.aws_x.y.id', 'count.index'],
                },
              },
            },
          ],
        },
      },
    });
    expect(overlay.configReferences).toBeUndefined();
  });
});
