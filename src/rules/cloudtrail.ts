import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import {
  findResources,
  findResourceLine,
  getNestedValue,
  findBaselineRemoteState,
  findCfnBaselineImports,
  cfnConditionOf,
  inconclusiveConditional,
} from '../utils/resource-helpers';
import { isUnresolvedScalar } from '../utils/literal';

const REGULATORY_REFERENCE =
  'EU AI Act Article 12(2) - Logging to enable traceability of events relevant to risk identification, post-market monitoring (Art. 72), and operation monitoring (Art. 26(5))';
const NIST_REFERENCE = 'NIST AI RMF 1.0: MANAGE 4.1 (post-deployment monitoring plans); GOVERN 1.4 (transparent risk-management policies); MEASURE 2.7 (security and resilience)';
const ISO_REFERENCE = 'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.3.3 (Reporting of concerns)';

const ADVICE =
  'Verify CloudTrail is enabled in your AWS account. If it is managed in a separate ' +
  'account-baseline stack, scan that stack or pass --strict-account-logging. ' +
  'If no trail exists, add an aws_cloudtrail resource with enable_logging = true.';

export const cloudtrailRule: ScanRule = {
  id: 'S-12.x.4',
  description: 'CloudTrail must exist and have logging enabled',
  severity: 'FAIL',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    // Thread the plan overlay so a trail declared inside a module (visible only
    // via planned_values, not the scanned HCL) is detected. Without it, a real
    // trail in a module falls through to INCONCLUSIVE/FAIL, inconsistent with
    // every other resource-scanning rule.
    const trails = findResources(files, 'aws_cloudtrail', context.planOverlay);

    // Trail(s) present - check whether logging is actually enabled.
    if (trails.length > 0) {
      return trails.map((trail) => {
        const enableLogging = getNestedValue(trail.body, 'enable_logging');
        const line = findResourceLine(trail.rawHcl, 'aws_cloudtrail', trail.name);

        // A Condition-guarded CFN trail may not exist at deploy time - its
        // properties cannot prove anything either way.
        const condition = cfnConditionOf(trail.body);
        if (condition) {
          return inconclusiveConditional(this, {
            label: `CloudTrail "${trail.name}"`,
            condition,
            filePath: trail.filePath,
            line,
          });
        }

        // enable_logging defaults to true in the AWS provider if not set.
        if (enableLogging === false) {
          return {
            ruleId: this.id,
            status: 'FAIL' as const,
            filePath: trail.filePath,
            line,
            description: `CloudTrail "${trail.name}" has enable_logging set to false - no control-plane events are being captured.`,
            remediation: 'Set enable_logging = true on the aws_cloudtrail resource.',
            regulatoryReference: REGULATORY_REFERENCE,
            nistReference: NIST_REFERENCE,
            isoReference: ISO_REFERENCE,
          };
        }

        // enable_logging driven by a var/local/data/module reference - we
        // cannot prove the trail is actually capturing events.
        if (isUnresolvedScalar(enableLogging)) {
          return {
            ruleId: this.id,
            status: 'INCONCLUSIVE' as const,
            filePath: trail.filePath,
            line,
            description: `CloudTrail "${trail.name}" has enable_logging set to a non-literal expression (${enableLogging}); the scanner cannot determine whether the trail will capture events.`,
            remediation:
              'Inline a literal enable_logging = true (or omit the attribute - it defaults to true), ' +
              'or rerun the scan against terraform plan output where the reference is resolved.',
            regulatoryReference: REGULATORY_REFERENCE,
            nistReference: NIST_REFERENCE,
            isoReference: ISO_REFERENCE,
          };
        }

        return {
          ruleId: this.id,
          status: 'PASS' as const,
          filePath: trail.filePath,
          line,
          description: `CloudTrail "${trail.name}" is configured with logging enabled.`,
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        };
      });
    }

    // No trail in scanned files. Check for baseline-stack evidence first -
    // a data.terraform_remote_state.account_baseline / audit / security / etc.
    // (or the CFN equivalent: Fn::ImportValue of a baseline-named export)
    // strongly implies the trail lives in a separate stack that wasn't scanned.
    const baselineHints = findBaselineRemoteState(files);
    const cfnImportHints = findCfnBaselineImports(files);
    if (baselineHints.length > 0 || cfnImportHints.length > 0) {
      const refs = [
        ...baselineHints.map((h) => h.dataAddress),
        ...cfnImportHints.map((h) => `Fn::ImportValue "${h.importName}"`),
      ].join(', ');
      return [
        {
          ruleId: this.id,
          status: 'INCONCLUSIVE' as const,
          filePath: '',
          description:
            `No aws_cloudtrail found in scanned files, but baseline remote-state ` +
            `reference(s) ${refs} suggest account-level infrastructure (including ` +
            `CloudTrail) is managed in a separate stack. Compliance cannot be verified ` +
            `from these files alone.`,
          remediation: ADVICE,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    // No trail, no cross-stack evidence. In strict mode this is a hard FAIL.
    // In default (permissive) mode it is INCONCLUSIVE - CloudTrail is typically
    // an account-baseline resource; a single-app stack not declaring it is not
    // proof that it doesn't exist in the account.
    if (context.strictAccountLogging) {
      return [
        {
          ruleId: this.id,
          status: 'FAIL' as const,
          filePath: '',
          description:
            'No aws_cloudtrail resource found in scanned files. ' +
            '(Strict account-logging mode: missing CloudTrail treated as FAIL.)',
          remediation:
            'Add an aws_cloudtrail resource with enable_logging = true (and is_multi_region_trail = true ' +
            'for production), or scan the account-baseline stack where the trail is defined. ' +
            'Why: CloudTrail is the only AWS service that records control-plane events ' +
            '(who created/modified/deleted Bedrock resources, IAM grants, log buckets). ' +
            'Without it, an Article 12 audit cannot reconstruct *who changed the AI system* ' +
            'or *when guardrails were modified* - the model-invocation logs alone do not capture this.',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    return [
      {
        ruleId: this.id,
        status: 'INCONCLUSIVE' as const,
        filePath: '',
        description:
          'No aws_cloudtrail found in scanned files and no cross-stack evidence detected. ' +
          'Why inconclusive: CloudTrail is typically managed in a separate account-baseline ' +
          'stack. The scanner cannot tell from this directory alone whether a trail exists ' +
          'elsewhere in your AWS account or is genuinely missing.',
        remediation: ADVICE,
        regulatoryReference: REGULATORY_REFERENCE,
        nistReference: NIST_REFERENCE,
        isoReference: ISO_REFERENCE,
      },
    ];
  },
};
