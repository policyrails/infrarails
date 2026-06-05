import { describe, it, expect } from 'vitest';
import { buildGuardrailGraph } from '../../src/utils/guardrail-graph';
import { parsePlanObject } from '../../src/plan-parser';
import { makeParsedFile } from './rules/helpers';

// hcl2json emits a resource reference like
//   guardrail_identifier = aws_bedrock_guardrail.filter.guardrail_id
// as the interpolation-wrapped string below.
function ref(name: string, attr = 'guardrail_id'): string {
  return `\${aws_bedrock_guardrail.${name}.${attr}}`;
}

function agent(name: string, identifier?: string): Record<string, unknown> {
  const body: Record<string, unknown> = { agent_name: name };
  if (identifier !== undefined) {
    body.guardrail_configuration = [{ guardrail_identifier: identifier, guardrail_version: '1' }];
  }
  return body;
}

describe('buildGuardrailGraph', () => {
  it('links a reference to a guardrail declared in scope', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: { support_bot: [agent('support-bot', ref('filter'))] },
        aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] },
      }),
    ];

    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('support_bot')).toEqual({ kind: 'declared', guardrail: 'filter' });
    expect(guardrailToAgents.get('filter')).toEqual(['support_bot']);
  });

  it('marks a reference to a guardrail not in scope as reference-external', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: { support_bot: [agent('support-bot', ref('platform_gr'))] },
      }),
    ];

    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('support_bot')).toEqual({
      kind: 'reference-external',
      guardrail: 'platform_gr',
    });
    // External references never populate the declared-guardrail index.
    expect(guardrailToAgents.size).toBe(0);
  });

  it('treats a literal ID / ARN as opaque (literal)', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          bot_id: [agent('bot-id', 'abcd1234')],
          bot_arn: [agent('bot-arn', 'arn:aws:bedrock:us-east-1:123456789012:guardrail/abcd1234')],
        },
      }),
    ];

    const { agentToGuardrail } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('bot_id')).toEqual({ kind: 'literal' });
    expect(agentToGuardrail.get('bot_arn')).toEqual({ kind: 'literal' });
  });

  it('marks var/local/module expressions as unresolved', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          v: [agent('v', '${var.guardrail_id}')],
          l: [agent('l', 'local.gr')],
          m: [agent('m', '${module.security.guardrail_id}')],
        },
      }),
    ];

    const { agentToGuardrail } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('v')).toEqual({ kind: 'unresolved' });
    expect(agentToGuardrail.get('l')).toEqual({ kind: 'unresolved' });
    expect(agentToGuardrail.get('m')).toEqual({ kind: 'unresolved' });
  });

  it('marks an agent with no guardrail_configuration (or empty identifier) as none', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          bare: [agent('bare')],
          empty: [agent('empty', '   ')],
        },
      }),
    ];

    const { agentToGuardrail } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('bare')).toEqual({ kind: 'none' });
    expect(agentToGuardrail.get('empty')).toEqual({ kind: 'none' });
  });

  it('collects multiple agents attaching the same declared guardrail', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          support_bot: [agent('support-bot', ref('filter'))],
          billing_bot: [agent('billing-bot', ref('filter', 'id'))],
        },
        aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] },
      }),
    ];

    const { guardrailToAgents } = buildGuardrailGraph(files);

    expect(guardrailToAgents.get('filter')).toEqual(['support_bot', 'billing_bot']);
  });

  it('returns empty maps when there are no agents', () => {
    const files = [
      makeParsedFile({ aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] } }),
    ];

    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph(files);

    expect(agentToGuardrail.size).toBe(0);
    expect(guardrailToAgents.size).toBe(0);
  });
});

describe('buildGuardrailGraph - cross-module resolution via plan configuration', () => {
  // Agent (module recruiter_api) attaches a guardrail (module bedrock_governance)
  // whose identifier/version are known-after-apply, plumbed through module
  // outputs. Only the configuration reference graph can prove this.
  function crossModulePlan(opts?: { breakChain?: boolean; draftVersion?: boolean }) {
    const idOutputRefs = opts?.breakChain
      ? ['aws_bedrock_guardrail.somewhere_else.guardrail_arn']
      : ['aws_bedrock_guardrail.recruiter.guardrail_arn'];
    const versionOutput = opts?.draftVersion
      ? { expression: { constant_value: 'DRAFT' } }
      : { expression: { references: ['aws_bedrock_guardrail_version.recruiter.version'] } };
    return {
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.bedrock_governance',
              resources: [
                {
                  address: 'module.bedrock_governance.aws_bedrock_guardrail.recruiter',
                  type: 'aws_bedrock_guardrail',
                  name: 'recruiter',
                  values: {},
                },
              ],
            },
            {
              address: 'module.recruiter_api',
              resources: [
                {
                  address: 'module.recruiter_api.aws_bedrockagent_agent.recruiter',
                  type: 'aws_bedrockagent_agent',
                  name: 'recruiter',
                  values: { guardrail_configuration: [{}] },
                },
              ],
            },
          ],
        },
      },
      configuration: {
        root_module: {
          module_calls: {
            recruiter_api: {
              expressions: {
                guardrail_identifier: {
                  references: ['module.bedrock_governance.guardrail_identifier'],
                },
                guardrail_version: {
                  references: ['module.bedrock_governance.guardrail_version'],
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
                  guardrail_identifier: { expression: { references: idOutputRefs } },
                  guardrail_version: versionOutput,
                },
              },
            },
          },
        },
      },
    };
  }

  it('resolves a known-after-apply identifier to a declared-via-module link', () => {
    const overlay = parsePlanObject(crossModulePlan());
    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph([], overlay);

    expect(agentToGuardrail.get('recruiter')).toEqual({
      kind: 'declared-via-module',
      guardrail: 'recruiter',
      versionPin: 'versioned',
    });
    expect(guardrailToAgents.get('recruiter')).toEqual(['recruiter']);
  });

  it('reports versionPin "unknown" when the chain reaches no guardrail_version resource', () => {
    const overlay = parsePlanObject(crossModulePlan({ draftVersion: true }));
    const { agentToGuardrail } = buildGuardrailGraph([], overlay);
    expect(agentToGuardrail.get('recruiter')).toEqual({
      kind: 'declared-via-module',
      guardrail: 'recruiter',
      versionPin: 'unknown',
    });
  });

  it('does not record an edge when the chain ends at a guardrail not in scope', () => {
    const overlay = parsePlanObject(crossModulePlan({ breakChain: true }));
    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph([], overlay);
    // 'somewhere_else' is not a declared guardrail, so no terminal matches.
    expect(agentToGuardrail.get('recruiter')).toEqual({ kind: 'none' });
    expect(guardrailToAgents.size).toBe(0);
  });

  it('falls back to today’s behaviour when the overlay has no configReferences', () => {
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.recruiter_api',
              resources: [
                {
                  address: 'module.recruiter_api.aws_bedrockagent_agent.recruiter',
                  type: 'aws_bedrockagent_agent',
                  name: 'recruiter',
                  values: { guardrail_configuration: [{}] },
                },
              ],
            },
          ],
        },
      },
    });
    expect(overlay.configReferences).toBeUndefined();
    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph([], overlay);
    expect(agentToGuardrail.get('recruiter')).toEqual({ kind: 'none' });
    expect(guardrailToAgents.size).toBe(0);
  });

  it('resolves a count/for_each agent whose plan address carries an instance index', () => {
    // The plan expands the agent into indexed instances (recruiter[0]); the
    // configuration block is pre-expansion (no index). Resolution must still
    // match the indexed plan address to its index-free config entry.
    const plan = crossModulePlan();
    plan.planned_values.root_module.child_modules[1].resources[0].address =
      'module.recruiter_api.aws_bedrockagent_agent.recruiter[0]';
    const overlay = parsePlanObject(plan);
    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph([], overlay);

    expect(agentToGuardrail.get('recruiter')).toEqual({
      kind: 'declared-via-module',
      guardrail: 'recruiter',
      versionPin: 'versioned',
    });
    expect(guardrailToAgents.get('recruiter')).toEqual(['recruiter']);
  });

  it('resolves an object-typed module input accessed by attribute (var.guardrail.identifier)', () => {
    // The module takes a single object input `guardrail` and the agent reads
    // var.guardrail.identifier / .version. Both must reduce to the base input
    // name so the call-site binding (keyed by input name) is found.
    const overlay = parsePlanObject({
      format_version: '1.2',
      terraform_version: '1.7.5',
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: 'module.bedrock_governance',
              resources: [
                {
                  address: 'module.bedrock_governance.aws_bedrock_guardrail.recruiter',
                  type: 'aws_bedrock_guardrail',
                  name: 'recruiter',
                  values: {},
                },
              ],
            },
            {
              address: 'module.recruiter_api',
              resources: [
                {
                  address: 'module.recruiter_api.aws_bedrockagent_agent.recruiter',
                  type: 'aws_bedrockagent_agent',
                  name: 'recruiter',
                  values: { guardrail_configuration: [{}] },
                },
              ],
            },
          ],
        },
      },
      configuration: {
        root_module: {
          module_calls: {
            recruiter_api: {
              expressions: {
                guardrail: {
                  identifier: { references: ['module.bedrock_governance.guardrail_identifier'] },
                  version: { references: ['module.bedrock_governance.guardrail_version'] },
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
                        references: ['var.guardrail.identifier', 'var.guardrail.version'],
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
                    expression: { references: ['aws_bedrock_guardrail.recruiter.guardrail_arn'] },
                  },
                  guardrail_version: {
                    expression: { references: ['aws_bedrock_guardrail_version.recruiter.version'] },
                  },
                },
              },
            },
          },
        },
      },
    });
    const { agentToGuardrail } = buildGuardrailGraph([], overlay);
    expect(agentToGuardrail.get('recruiter')).toEqual({
      kind: 'declared-via-module',
      guardrail: 'recruiter',
      versionPin: 'versioned',
    });
  });

  it('keeps the strongest link when an agent is seen as both HCL and plan instance', () => {
    // HCL copy uses an unresolvable var ref; plan copy resolves via config refs.
    // Result must be order-independent and pick the resolved one.
    const overlay = parsePlanObject(crossModulePlan());
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          recruiter: [
            {
              agent_name: 'recruiter',
              guardrail_configuration: [
                { guardrail_identifier: '${var.guardrail_identifier}', guardrail_version: '${var.guardrail_version}' },
              ],
            },
          ],
        },
      }),
    ];
    const { agentToGuardrail } = buildGuardrailGraph(files, overlay);
    expect(agentToGuardrail.get('recruiter')).toEqual({
      kind: 'declared-via-module',
      guardrail: 'recruiter',
      versionPin: 'versioned',
    });
  });
});
