import { ScanRule, Finding, ParsedFile, PlanOverlay, ScanContext, UnresolvableReason } from '../types';
import { findResources, findResourceLine, getNestedValue, inconclusiveFromUnresolved, cfnConditionOf, inconclusiveConditional } from '../utils/resource-helpers';
import { resolveExpression, resolveOrPlanFallback, resolveScalarReference } from '../resolver';
import { isUnresolvedScalar } from '../utils/literal';

const MIN_RETENTION_DAYS = 180;
const RECOMMENDED_RETENTION_DAYS = 365;

// Logs are generated under Article 12(1) and retained under Article 19(1), which
// requires they be "kept for a period appropriate to the intended purpose of the
// high-risk AI system, of at least six months." That six-month minimum is the basis
// for the 180-day floor; the 365-day recommendation reflects the practical reality
// that high-risk AI incidents (bias drift, hallucinated decisions, downstream-deployer
// audits under Article 26, regulator queries under Article 72 post-market monitoring)
// surface months - often quarters - after the originating event. This rationale is
// surfaced in remediation messages so users understand the "why" behind the number.
const RETENTION_RATIONALE =
  'EU AI Act Art. 19(1) requires high-risk-system logs be kept "for a period ' +
  'appropriate to the intended purpose ... of at least six months" - that six-month ' +
  'minimum is the 180-day floor. Bias drift, hallucinated decisions, and ' +
  'downstream-deployer audits surface months after the event, so sub-180-day ' +
  'retention undermines post-market monitoring (Article 72) and incident ' +
  'investigation; 365 days is the typical floor for production AI.';

// A static IaC scan cannot prove what happens to logs after they leave the
// account: forwarders to Datadog/Splunk/SIEM are usually owned by a platform
// team in a separate Terraform repo (or deployed out-of-band via the Datadog
// CloudFormation template, StackSets, or auto-subscription Lambdas). A short
// or undeclared retention_in_days is therefore not proof of a compliance gap -
// it may be deliberate when a forwarder is shipping logs to a system that
// retains them. We WARN in every uncertain case rather than FAIL, and tailor
// the message based on whether a subscription filter was found in the scanned
// Terraform.
const FORWARDER_NOTE_WHEN_FOUND =
  'A CloudWatch subscription filter was found in the scanned IaC - ' +
  'logs may be forwarded to an external system (Datadog, Splunk, SIEM) where ' +
  'retention is satisfied. Verify the destination retention; this scanner ' +
  'cannot follow the chain past the subscription filter.';

const FORWARDER_NOTE_WHEN_MISSING =
  'No CloudWatch subscription filter was found in the scanned IaC, but ' +
  'forwarders are commonly owned by a separate platform repo (Datadog/Splunk ' +
  'forwarder Lambda, central log-archive account, auto-subscription Lambda). ' +
  'If logs are forwarded out-of-repo, verify retention at the destination. ' +
  'If they are not, this is a real compliance gap.';

function hasSubscriptionFilterFor(
  files: ParsedFile[],
  targetLogGroupName: string,
  overlay?: PlanOverlay,
): boolean {
  // Threading the overlay here matters in practice: Datadog/Splunk/SIEM
  // forwarder modules are commonly consumed as remote modules that take a
  // log group name (or ARN) as input and declare the subscription filter
  // internally. Without the overlay, the filter is invisible to the scanner
  // and the forwarder-aware path in cw-retention falsely escalates retention
  // findings to FAIL under --strict-account-logging.
  const filters = findResources(files, 'aws_cloudwatch_log_subscription_filter', overlay);
  for (const f of filters) {
    const lgName = getNestedValue(f.body, 'log_group_name');

    if (lgName === targetLogGroupName) return true;

    if (typeof lgName === 'string') {
      const result = resolveExpression(lgName, files, 'log_group_name', undefined, overlay);
      if (result?.kind === 'literal' && result.value === targetLogGroupName) return true;
      if (result?.kind === 'address' && result.value === targetLogGroupName) return true;
      if (result?.kind === 'address' && result.value === `aws_cloudwatch_log_group.${targetLogGroupName}`) return true;
    }
  }
  return false;
}

export const cwRetentionRule: ScanRule = {
  id: 'S-12.1.2a',
  description: 'CloudWatch log group retention - WARN-level (forwarders may satisfy retention out-of-repo)',
  severity: 'WARN',
  regulatoryReference: 'EU AI Act Article 19(1) - High-risk-system logs kept for an appropriate period, at least six months',
  nistReference: 'NIST AI RMF 1.0: MANAGE 4.1 (post-deployment monitoring plans); MANAGE 4.3 (incident communication to AI actors); MEASURE 3.2 (risk tracking across AI lifecycle)',
  isoReference: 'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (AI system operation and monitoring)',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. CloudWatch retention check skipped.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const ref of context.unresolvedGroupRefs) {
      findings.push(inconclusiveFromUnresolved(this, ref, 'log group'));
    }

    if (context.logGroupNames.length === 0 && context.unresolvedGroupRefs.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'Bedrock logging does not use CloudWatch. Skipping CloudWatch retention check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const logGroups = findResources(files, 'aws_cloudwatch_log_group', context.planOverlay);

    for (const targetName of context.logGroupNames) {
      const matching = logGroups.find((lg) => {
        const name = getNestedValue(lg.body, 'name');

        // Direct literal match
        if (name === targetName) return true;
        if (lg.name === targetName) return true;
        if (`aws_cloudwatch_log_group.${lg.name}` === targetName) return true;

        // Resolve variable/local references in the name attribute.
        // With overlay, fall back to the log group's own plan-resolved `name`
        // attribute when the expression is a complex interpolation.
        if (typeof name === 'string') {
          const result = resolveOrPlanFallback(
            name,
            `aws_cloudwatch_log_group.${lg.name}`,
            'name',
            files,
            'name',
            undefined,
            context.planOverlay,
          );
          if (result?.kind === 'literal' && result.value === targetName) return true;
          if (result?.kind === 'address' && result.value === targetName) return true;
        }

        return false;
      });

      if (!matching) {
        const forwarderFound = hasSubscriptionFilterFor(files, targetName, context.planOverlay);
        const escalate = context.strictAccountLogging && !forwarderFound;
        findings.push({
          ruleId: this.id,
          status: escalate ? 'FAIL' : 'WARN',
          filePath: '',
          description: escalate
            ? `CloudWatch log group "${targetName}" is referenced by Bedrock invocation logging but not declared in any scanned IaC file, and no CloudWatch subscription filter forwards it out-of-repo. (Strict account-logging mode: missing log group with no forwarder treated as FAIL.)`
            : `CloudWatch log group "${targetName}" is referenced by Bedrock invocation logging but not declared in any scanned IaC file - its retention is not under this repo's IaC control.`,
          remediation:
            `Either declare an aws_cloudwatch_log_group resource for "${targetName}" with ` +
            `retention_in_days >= ${MIN_RETENTION_DAYS} (recommended: ${RECOMMENDED_RETENTION_DAYS}), ` +
            `or confirm the log group is managed in another Terraform repo / central account. ` +
            `${forwarderFound ? FORWARDER_NOTE_WHEN_FOUND : FORWARDER_NOTE_WHEN_MISSING} ` +
            `Why retention matters: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
        continue;
      }

      const retention = getNestedValue(matching.body, 'retention_in_days');
      let retentionDays = typeof retention === 'number' ? retention : undefined;
      const line = findResourceLine(matching.rawHcl, 'aws_cloudwatch_log_group', matching.name);

      // Condition-guarded CFN log group: it (and its retention) may not exist
      // at deploy time, so neither PASS nor WARN/FAIL is honest.
      const condition = cfnConditionOf(matching.body);
      if (condition) {
        findings.push(
          inconclusiveConditional(this, {
            label: `CloudWatch log group "${targetName}"`,
            condition,
            filePath: matching.filePath,
            line,
          }),
        );
        continue;
      }

      // retention_in_days driven by a var/local reference - try to resolve it
      // against same-module variable defaults / locals before giving up. This
      // turns "INCONCLUSIVE because expression" into a real verdict whenever
      // the default is in the scanned repo.
      if (retentionDays === undefined && isUnresolvedScalar(retention)) {
        const resolved = resolveScalarReference(
          retention,
          files,
          matching.filePath,
          context.planOverlay,
        );
        if (resolved) {
          if (typeof resolved.value === 'number') {
            retentionDays = resolved.value;
          } else if (typeof resolved.value === 'string') {
            const parsed = Number(resolved.value);
            if (Number.isFinite(parsed)) retentionDays = parsed;
          }
        }
      }

      // Still unresolved after walking variable/local defaults - the value
      // is supplied at apply time (var with no default, module input, data
      // source, complex interpolation). Surface INCONCLUSIVE rather than
      // silently treating it as "not declared". Tag with the unresolvable
      // reason so the runner-side strict-mode post-processor can escalate
      // escalatable reasons to FAIL while leaving genuinely unknowable
      // ones (plan-known-after-apply, plan-sensitive-redacted) alone.
      if (retentionDays === undefined && isUnresolvedScalar(retention)) {
        let unresolvedReason: UnresolvableReason | undefined;
        const probe = resolveExpression(
          retention,
          files,
          'retention_in_days',
          matching.filePath,
          context.planOverlay,
        );
        if (probe?.kind === 'unresolvable') unresolvedReason = probe.reason;
        findings.push({
          ruleId: this.id,
          status: 'INCONCLUSIVE',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" has retention_in_days set to a non-literal expression (${retention}); the scanner cannot determine whether retention meets the ${MIN_RETENTION_DAYS}-day floor.`,
          remediation:
            `Inline a literal retention_in_days >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}), or rerun the scan against ` +
            `terraform plan output where the reference is resolved.`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
          unresolvedReason,
        });
        continue;
      }

      if (retentionDays === undefined || retentionDays === 0) {
        // retention_in_days = 0 means never expire - that's compliant.
        if (retentionDays === 0) {
          findings.push({
            ruleId: this.id,
            status: 'PASS',
            filePath: matching.filePath,
            line,
            description: `CloudWatch log group "${targetName}" has retention set to never expire (retention_in_days = 0).`,
            remediation: '',
            regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
          });
        } else {
          const forwarderFound = hasSubscriptionFilterFor(files, targetName, context.planOverlay);
          const escalate = context.strictAccountLogging && !forwarderFound;
          findings.push({
            ruleId: this.id,
            status: escalate ? 'FAIL' : 'WARN',
            filePath: matching.filePath,
            line,
            description: escalate
              ? `CloudWatch log group "${targetName}" has no retention_in_days declared and no CloudWatch subscription filter forwards it out-of-repo. (Strict account-logging mode: missing retention with no forwarder treated as FAIL.)`
              : `CloudWatch log group "${targetName}" has no retention_in_days declared. Behaviour falls back to whatever was previously set in AWS - local retention is not under IaC control.`,
            remediation:
              `Set retention_in_days explicitly: a value >= ${MIN_RETENTION_DAYS} ` +
              `(recommended: ${RECOMMENDED_RETENTION_DAYS}), or 0 for never-expire. ` +
              `${forwarderFound ? FORWARDER_NOTE_WHEN_FOUND : FORWARDER_NOTE_WHEN_MISSING} ` +
              `Why retention matters: ${RETENTION_RATIONALE}`,
            regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
          });
        }
      } else if (retentionDays < MIN_RETENTION_DAYS) {
        const forwarderFound = hasSubscriptionFilterFor(files, targetName, context.planOverlay);
        const escalate = context.strictAccountLogging && !forwarderFound;
        findings.push({
          ruleId: this.id,
          status: escalate ? 'FAIL' : 'WARN',
          filePath: matching.filePath,
          line,
          description: escalate
            ? `CloudWatch log group "${targetName}" retention is ${retentionDays} days (below the ${MIN_RETENTION_DAYS}-day floor) and no CloudWatch subscription filter forwards it out-of-repo. (Strict account-logging mode: sub-floor retention with no forwarder treated as FAIL.)`
            : `CloudWatch log group "${targetName}" retention is ${retentionDays} days, below the ${MIN_RETENTION_DAYS}-day floor infrarails applies for high-risk AI logging.`,
          remediation:
            `Increase retention_in_days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}), or confirm retention is ` +
            `satisfied by a forwarder destination / central log-archive account. ` +
            `${forwarderFound ? FORWARDER_NOTE_WHEN_FOUND : FORWARDER_NOTE_WHEN_MISSING} ` +
            `Why retention matters: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else if (retentionDays < RECOMMENDED_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days. infrarails recommends >= ${RECOMMENDED_RETENTION_DAYS} days for production AI workloads.`,
          remediation:
            `Consider increasing retention_in_days to ${RECOMMENDED_RETENTION_DAYS}. ` +
            `Why: 365 days covers most regulator-inquiry windows, calendar-quarter audit ` +
            `cycles, and the typical lag between an AI incident and its discovery downstream.`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      }
    }

    return findings;
  },
};
