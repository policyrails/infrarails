import { ScanRule, Finding, FindingDetail, ParsedFile, ScanContext } from '../types';
import {
  findResources,
  findResourceLine,
  getNestedValue,
  findRemoteModules,
  findBedrockResources,
  findBedrockDataSources,
  findIamBedrockGrants,
  findBedrockVpcEndpoints,
  isCfnTemplatePath,
} from '../utils/resource-helpers';
import { isUnresolvedScalar } from '../utils/literal';

const MODALITY_TOGGLES = [
  'text_data_delivery_enabled',
  'image_data_delivery_enabled',
  'embedding_data_delivery_enabled',
  'video_data_delivery_enabled',
];

const REGULATORY_REFERENCE = 'EU AI Act Article 12(1) - Automatic logging of events';
const NIST_REFERENCE = 'NIST AI RMF 1.0: GOVERN 1.4 (transparent risk-management policies); MEASURE 2.7 (security and resilience); MANAGE 4.1 (post-deployment monitoring plans)';
const ISO_REFERENCE = 'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (AI system operation and monitoring)';

const RUN_PLAN_HINT =
  'Run infrarails against "terraform show -json plan.json" for full apply-time resolution, or scan the stack/module that defines the missing pieces.';

interface DirectUsage {
  resourceAddress: string;
  type: string;
  filePath: string;
}

interface IndirectUsage {
  iam: ReturnType<typeof findIamBedrockGrants>;
  vpc: ReturnType<typeof findBedrockVpcEndpoints>;
  dataSources: ReturnType<typeof findBedrockDataSources>;
}

export const bedrockLoggingRule: ScanRule = {
  id: 'S-12.1.1',
  description: 'Bedrock model invocation logging must be configured when Bedrock is in use',
  severity: 'FAIL',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,
  phase1: true,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    const overlay = context.planOverlay;
    const configs = findResources(
      files,
      'aws_bedrock_model_invocation_logging_configuration',
      overlay,
    );
    const agentResources = findResources(files, 'aws_bedrockagent_agent', overlay);
    const hasAgent = agentResources.length > 0;
    const agentNames = agentResources.map((a) => a.name);

    // Logging config present in scanned files - PASS / modality-FAIL.
    if (configs.length > 0) {
      return configs.map((config) => evaluateLoggingConfig(config, hasAgent, agentNames));
    }

    const direct: DirectUsage[] = findBedrockResources(files, overlay).map((r) => ({
      resourceAddress: r.resourceAddress,
      type: r.type,
      filePath: r.filePath,
    }));
    const indirect: IndirectUsage = {
      iam: findIamBedrockGrants(files),
      vpc: findBedrockVpcEndpoints(files),
      dataSources: findBedrockDataSources(files),
    };

    const hasDirect = direct.length > 0;
    const hasIndirect =
      indirect.iam.length > 0 || indirect.vpc.length > 0 || indirect.dataSources.length > 0;

    // No Bedrock signals at all. SKIP, unless there are unscannable remote
    // modules - in which case INCONCLUSIVE because Bedrock may live inside.
    // With --plan, remote module contents are visible via the overlay
    // (planned_values.child_modules), so findBedrockResources(files, overlay)
    // has already searched them - absence here means they truly contain no
    // Bedrock resources and a clean SKIP is correct.
    if (!hasDirect && !hasIndirect) {
      const remoteModules = findRemoteModules(files);
      if (remoteModules.length === 0 || overlay) {
        return [
          {
            ruleId: this.id,
            status: 'SKIP',
            filePath: '',
            description: 'No Bedrock resources detected. Invocation logging check skipped.',
            remediation: '',
            regulatoryReference: REGULATORY_REFERENCE,
            nistReference: NIST_REFERENCE,
            isoReference: ISO_REFERENCE,
          },
        ];
      }
      return [buildRemoteModuleInconclusive(this.id, remoteModules)];
    }

    // All Bedrock-usage signals come from CloudFormation templates. CFN has
    // no resource type for Bedrock model invocation logging (the TF
    // aws_bedrock_model_invocation_logging_configuration has no CFN
    // counterpart - AWS's own guidance uses a Lambda-backed custom resource
    // calling the API), so the scanned templates *cannot* declare it. The
    // honest verdict is INCONCLUSIVE - even under --strict-account-logging,
    // because logging may be configured via the API/console/custom resource
    // and a FAIL would demand a fix CFN cannot express.
    const signalPaths = [
      ...direct.map((d) => d.filePath),
      ...indirect.iam.map((g) => g.filePath),
      ...indirect.vpc.map((v) => v.filePath),
      ...indirect.dataSources.map((d) => d.filePath),
    ];
    if (signalPaths.length > 0 && signalPaths.every((p) => isCfnTemplatePath(p))) {
      return [buildCfnLoggingGapInconclusive(this.id, direct, indirect, hasAgent, agentNames)];
    }

    // Indirect-only signals (IAM / VPC / data source) and no logging.
    // The deploying resource may be in another stack, so this is never a
    // confident FAIL even under strict mode.
    if (!hasDirect) {
      return [buildIndirectOnlyInconclusive(this.id, indirect)];
    }

    // Direct Bedrock usage with no logging config in scanned files.
    // Strict mode: the user is asserting this directory is the entire estate,
    // so missing logging is a hard FAIL.
    // Permissive mode: logging may legitimately live in another stack -
    // emit INCONCLUSIVE and let the user decide.
    if (context.strictAccountLogging) {
      return [buildStrictModeFail(this.id, direct, indirect, hasAgent, agentNames)];
    }
    return [buildPermissiveInconclusive(this.id, direct, indirect, hasAgent, agentNames)];
  },
};

function evaluateLoggingConfig(
  config: {
    name: string;
    body: Record<string, unknown>;
    filePath: string;
    rawHcl: string;
  },
  hasAgent: boolean,
  agentNames: string[],
): Finding {
  const line = findResourceLine(
    config.rawHcl,
    'aws_bedrock_model_invocation_logging_configuration',
    config.name,
  );
  const loggingConfig = getNestedValue(config.body, 'logging_config');
  const agentContext = agentScopeContext(hasAgent, agentNames);

  const explicitlyDisabled: string[] = [];
  const explicitlyEnabled: string[] = [];
  const unresolvedToggles: string[] = [];
  for (const toggle of MODALITY_TOGGLES) {
    const value = getNestedValue(loggingConfig, toggle);
    if (value === undefined) continue;
    if (value === false) explicitlyDisabled.push(toggle);
    else if (value === true) explicitlyEnabled.push(toggle);
    else if (isUnresolvedScalar(value)) unresolvedToggles.push(toggle);
  }

  // If any modality toggle is driven by a var/local/data/module reference, we
  // cannot statically determine whether logging will actually deliver events.
  // Report INCONCLUSIVE rather than falling through to the all-disabled FAIL
  // check (which silently passes when toggles aren't literal `false`).
  if (unresolvedToggles.length > 0) {
    return {
      ruleId: 'S-12.1.1',
      status: 'INCONCLUSIVE',
      filePath: config.filePath,
      line,
      description:
        `Bedrock logging resource "${config.name}" has non-literal modality toggle(s): ` +
        `${unresolvedToggles.join(', ')}. Their effective value depends on a Terraform ` +
        `variable, local, data source, or module output and cannot be evaluated from source alone.`,
      remediation:
        `Inline literal true/false for *_data_delivery_enabled toggles, omit them entirely ` +
        `(AWS enables all modalities by default when unset), or rerun the scan against ` +
        `terraform plan output where references are resolved. Why: an expression-driven ` +
        `toggle can hide an all-disabled config that AWS will accept but never write events for.`,
      ...(agentContext.length > 0 ? { context: agentContext } : {}),
      regulatoryReference: REGULATORY_REFERENCE,
      nistReference: NIST_REFERENCE,
      isoReference: ISO_REFERENCE,
    };
  }

  if (explicitlyEnabled.length === 0 && explicitlyDisabled.length === MODALITY_TOGGLES.length) {
    return {
      ruleId: 'S-12.1.1',
      status: 'FAIL',
      filePath: config.filePath,
      line,
      description: `Bedrock logging resource "${config.name}" exists but every *_data_delivery_enabled toggle is set to false - AWS will accept this configuration, but no invocations will actually be written.`,
      remediation:
        `Set at least one of ${MODALITY_TOGGLES.join(', ')} to true on logging_config ` +
        `(or remove the toggles entirely - when unset, AWS enables all modalities by default). ` +
        `Why: this is one of the most common Article 12 failure modes - the resource exists, ` +
        `Terraform applies cleanly, dashboards look "configured", but the log destination ` +
        `stays empty. Verify with the AWS console or "aws bedrock get-model-invocation-logging-configuration".`,
      ...(agentContext.length > 0 ? { context: agentContext } : {}),
      regulatoryReference: REGULATORY_REFERENCE,
      nistReference: NIST_REFERENCE,
      isoReference: ISO_REFERENCE,
    };
  }

  const passDescription = hasAgent
    ? `Bedrock invocation logging is configured (${config.name}). Note: Bedrock Agent(s) detected (${agentNames.join(', ')}) - this captures the model leg only. Verify enableTrace=true is set on InvokeAgent calls and that action-group Lambdas have their own log groups for full Article 12 trace coverage.`
    : `Bedrock invocation logging is configured (${config.name}).`;

  return {
    ruleId: 'S-12.1.1',
    status: 'PASS',
    filePath: config.filePath,
    line,
    description: passDescription,
    remediation: '',
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

/**
 * The agent caveat as labeled supporting observations rather than a sentence
 * glued onto the end of `remediation`. Bedrock invocation logging covers only
 * the model leg of an InvokeAgent call, so for agents it is necessary but not
 * sufficient - splitting that into short `context[]` lines keeps the headline
 * fix scannable instead of burying it under a ~90-word run readers skip.
 * Returns [] when no agent is present, so non-agent findings carry no context.
 */
function agentScopeContext(hasAgent: boolean, agentNames: string[]): FindingDetail[] {
  if (!hasAgent) return [];
  return [
    {
      label: 'Agent scope',
      text:
        `Agent(s) detected (${agentNames.join(', ')}): invocation logging captures only the ` +
        `model leg of an InvokeAgent call - necessary, but not sufficient for an agent.`,
    },
    {
      label: 'Also required',
      text:
        'enableTrace=true on each InvokeAgent call (application-level, not IaC), plus CloudWatch ' +
        'log groups for any action-group Lambdas at the same retention as model logs.',
    },
    {
      label: 'If missing',
      text: 'Reasoning steps, action-group invocations, and knowledge-base retrievals are not auditable.',
    },
  ];
}

function buildRemoteModuleInconclusive(
  ruleId: string,
  remoteModules: ReturnType<typeof findRemoteModules>,
): Finding {
  const names = remoteModules.map((m) => `"${m.name}"`).join(', ');
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `No Bedrock resources found in scanned files, but remote module(s) ${names} could not be inspected. Bedrock usage and logging config may be defined inside those modules.`,
    remediation: RUN_PLAN_HINT,
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

function buildCfnLoggingGapInconclusive(
  ruleId: string,
  direct: DirectUsage[],
  indirect: IndirectUsage,
  hasAgent: boolean,
  agentNames: string[],
): Finding {
  const usageSummary = describeUsage(direct, indirect);
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: direct[0]?.filePath ?? '',
    description:
      `${usageSummary} Bedrock usage was detected in CloudFormation template(s), but ` +
      `CloudFormation has no resource type for Bedrock model invocation logging, so the ` +
      `scanned templates cannot declare it. Whether logging is enabled cannot be ` +
      `determined from these files.`,
    remediation:
      'Enable Bedrock invocation logging outside CloudFormation - via the console/API ' +
      '(PutModelInvocationLoggingConfiguration), a Lambda-backed custom resource, or a ' +
      'Terraform stack declaring aws_bedrock_model_invocation_logging_configuration. ' +
      'Verify: aws bedrock get-model-invocation-logging-configuration. If a ' +
      'Terraform stack manages it, scan that directory too.',
    ...(hasAgent ? { context: agentScopeContext(hasAgent, agentNames) } : {}),
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

function buildIndirectOnlyInconclusive(ruleId: string, indirect: IndirectUsage): Finding {
  const usageSummary = describeUsage([], indirect);
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_* resource and no logging config detected in scanned files. The deploying resource and logging may live in another stack.`,
    remediation: RUN_PLAN_HINT,
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

function buildStrictModeFail(
  ruleId: string,
  direct: DirectUsage[],
  indirect: IndirectUsage,
  hasAgent: boolean,
  agentNames: string[],
): Finding {
  const usageSummary = describeUsage(direct, indirect);
  return {
    ruleId,
    status: 'FAIL',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_model_invocation_logging_configuration is defined in scanned files. (Strict account-logging mode: missing logging treated as FAIL.)`,
    remediation:
      'Add an aws_bedrock_model_invocation_logging_configuration resource pointing at a ' +
      'CloudWatch log group or S3 bucket - and enable at least one of text_data_delivery_enabled, ' +
      'image_data_delivery_enabled, embedding_data_delivery_enabled, or video_data_delivery_enabled. ' +
      'Why: Article 12(1) mandates *automatic* recording of events throughout the AI system\'s ' +
      'operational lifetime. Without invocation logging, you have no record of what prompts were ' +
      'sent, what responses were returned, or which model version produced them - making bias ' +
      'investigation, hallucination forensics, and downstream-deployer audits impossible.',
    ...(hasAgent ? { context: agentScopeContext(hasAgent, agentNames) } : {}),
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

function buildPermissiveInconclusive(
  ruleId: string,
  direct: DirectUsage[],
  indirect: IndirectUsage,
  hasAgent: boolean,
  agentNames: string[],
): Finding {
  const usageSummary = describeUsage(direct, indirect);
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_model_invocation_logging_configuration found in scanned files. If logging is configured in a separate stack, scan that directory too. Pass --strict-account-logging if this directory covers the entire infra estate and missing logging should be treated as FAIL.`,
    remediation: RUN_PLAN_HINT,
    ...(hasAgent ? { context: agentScopeContext(hasAgent, agentNames) } : {}),
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

function describeUsage(direct: DirectUsage[], indirect: IndirectUsage): string {
  const parts: string[] = [];
  if (direct.length > 0) {
    parts.push(
      `Bedrock direct usage detected (${direct.length} resource(s): ${direct.map((d) => d.resourceAddress).join(', ')}).`,
    );
  }
  if (indirect.iam.length > 0) {
    parts.push(
      `IAM grant(s) for Bedrock actions on ${indirect.iam
        .map((g) => `${g.resourceAddress} (${g.actions.join(', ')})`)
        .join('; ')}.`,
    );
  }
  if (indirect.vpc.length > 0) {
    parts.push(
      `VPC endpoint(s) to Bedrock service: ${indirect.vpc
        .map((v) => `${v.resourceAddress} (${v.serviceName})`)
        .join('; ')}.`,
    );
  }
  if (indirect.dataSources.length > 0) {
    parts.push(
      `Bedrock data source(s) referenced: ${indirect.dataSources.map((d) => d.dataAddress).join(', ')}.`,
    );
  }
  return parts.join(' ');
}
