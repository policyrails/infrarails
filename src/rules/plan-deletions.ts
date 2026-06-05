import { ScanRule, Finding, ParsedFile, ScanContext, PlanDeletion } from '../types';
import { getNestedValue } from '../utils/resource-helpers';

const REGULATORY_REFERENCE =
  'EU AI Act Article 12(1) - Automatic logging of events must be preserved across infra changes';
// Lifecycle-configuration deletions are a *retention* concern, not a logging
// one: removing the lifecycle rule drops the enforced retention floor. That
// obligation lives in Art. 19(1), not Art. 12(1).
const RETENTION_REGULATORY_REFERENCE =
  'EU AI Act Article 19(1) - High-risk-system logs kept for an appropriate period, at least six months (retention controls must survive infra changes)';
const NIST_REFERENCE =
  'NIST AI RMF 1.0: MANAGE 4.1 (post-deployment monitoring plans); GOVERN 1.4 (transparent risk-management policies)';
const ISO_REFERENCE =
  'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (AI system operation and monitoring)';

/**
 * In-scope deletion-finding rules. A direct hit on the type emits FAIL
 * unconditionally; bucket/log-group deletions are FAIL only when the
 * destroyed resource is referenced by Bedrock invocation logging in this
 * scan's context.
 *
 * Replacement actions (create+delete in either order) downgrade to WARN.
 * For types with a dedicated downstream rule (bedrock logging config,
 * s3 encryption config), the replacement's compliance is verified by that
 * rule on the new state's own merits - no cross-check against the old
 * state is needed here. For types without a dedicated rule (metric_filter,
 * metric_alarm), the scanner only enforces existence; replacement preserves
 * existence, so WARN is honest.
 */
const ALWAYS_FAIL_TYPES = new Set<string>([
  'aws_bedrock_model_invocation_logging_configuration',
  'aws_s3_bucket_server_side_encryption_configuration',
  'aws_cloudwatch_log_metric_filter',
  'aws_cloudwatch_metric_alarm',
]);

export const planDeletionsRule: ScanRule = {
  id: 'S-12.x.del',
  description:
    'Plan must not destroy logging, retention, or monitoring resources that satisfy Article 12.',
  severity: 'FAIL',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,

  run(_files: ParsedFile[], context: ScanContext): Finding[] {
    const overlay = context.planOverlay;
    if (!overlay) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description:
            'No plan supplied (--plan). Deletion analysis requires a Terraform plan JSON.',
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    // Zero deletions covers two plan shapes that look identical in JSON:
    // a true `-refresh-only` plan, and a normal apply plan against
    // infrastructure already in the desired state. Both honestly answer
    // "no deletions scheduled" -> PASS. We append a generic disclaimer when
    // the parser detected the all-no-op shape so reviewers know to rerun
    // with a real apply plan if the intent was deletion-safety verification.
    if (overlay.deletions.size === 0) {
      const description = overlay.flags.noActionableChanges
        ? 'Plan does not destroy any resources. Note: this plan contains no ' +
          'create/update/delete actions, which is also the shape of a ' +
          '`terraform plan -refresh-only` output. Refresh-only plans cannot ' +
          'represent deletions - if you generated one, rerun with a normal ' +
          '`terraform plan` so deletion-safety can be verified against the ' +
          'changes you actually intend to apply.'
        : 'Plan does not destroy any resources.';
      return [
        {
          ruleId: this.id,
          status: 'PASS',
          filePath: '',
          description,
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const deletion of overlay.deletions.values()) {
      const finding = classifyDeletion(deletion, context);
      if (finding) findings.push(finding);
    }

    if (findings.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'PASS',
          filePath: '',
          description:
            'Plan destroys resources but none are in the Article 12 logging/retention/monitoring scope.',
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    return findings;
  },
};

function classifyDeletion(deletion: PlanDeletion, context: ScanContext): Finding | undefined {
  const { type, address, before, replaceWithCreate } = deletion;
  const filePath = `plan:${address}`;

  // Always-FAIL types: any deletion is a compliance event.
  if (ALWAYS_FAIL_TYPES.has(type)) {
    return buildDeletionFinding({
      type,
      address,
      before,
      replaceWithCreate,
      filePath,
      description: describeAlwaysFail(type, address, before),
      remediation: remediationFor(type),
    });
  }

  // Log-destination buckets/log groups: FAIL only when the destroyed resource
  // is referenced by Bedrock logging in this scan's resolved context.
  if (type === 'aws_s3_bucket') {
    const bucketName = typeof before.bucket === 'string' ? before.bucket : undefined;
    if (!isLogBucket(bucketName, deletion.name, context)) return undefined;
    return buildDeletionFinding({
      type,
      address,
      before,
      replaceWithCreate,
      filePath,
      description: `S3 log bucket "${bucketName ?? deletion.name}" (${address}) is scheduled for destruction; Bedrock invocation log storage will be removed.`,
      remediation:
        'Keep the bucket, or migrate Bedrock logging to its replacement before applying this plan. ' +
        'Without the log destination, Article 12 invocation logs stop being persisted.',
    });
  }

  if (type === 'aws_cloudwatch_log_group') {
    const lgName = typeof before.name === 'string' ? before.name : undefined;
    if (!isLogGroup(lgName, deletion.name, context)) return undefined;
    return buildDeletionFinding({
      type,
      address,
      before,
      replaceWithCreate,
      filePath,
      description: `CloudWatch log group "${lgName ?? deletion.name}" (${address}) is scheduled for destruction; Bedrock invocation log destination will be removed.`,
      remediation:
        'Keep the log group, or migrate Bedrock logging to its replacement before applying this plan. ' +
        'Without the destination, Article 12 invocation logs stop being persisted.',
    });
  }

  if (type === 'aws_s3_bucket_lifecycle_configuration') {
    const bucket = typeof before.bucket === 'string' ? before.bucket : undefined;
    if (!isLogBucket(bucket, deletion.name, context)) return undefined;
    return buildDeletionFinding({
      type,
      address,
      before,
      replaceWithCreate,
      filePath,
      description: `Lifecycle configuration for log bucket "${bucket ?? deletion.name}" (${address}) is scheduled for destruction; retention controls will be removed.`,
      remediation:
        'Keep the lifecycle configuration, or replace it with another rule meeting the 180-day floor before applying.',
      regulatoryReference: RETENTION_REGULATORY_REFERENCE,
    });
  }

  return undefined;
}

function buildDeletionFinding(args: {
  type: string;
  address: string;
  before: Record<string, unknown>;
  replaceWithCreate: boolean;
  filePath: string;
  description: string;
  remediation: string;
  // Defaults to the Art. 12(1) logging citation; the lifecycle-config branch
  // overrides with the Art. 19(1) retention citation.
  regulatoryReference?: string;
}): Finding {
  const status = args.replaceWithCreate ? 'WARN' : 'FAIL';
  const description = args.replaceWithCreate
    ? `${args.description} The plan also creates a replacement; expect a brief gap during apply.`
    : args.description;
  return {
    ruleId: 'S-12.x.del',
    status,
    filePath: args.filePath,
    description,
    remediation: args.remediation,
    regulatoryReference: args.regulatoryReference ?? REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };
}

function describeAlwaysFail(type: string, address: string, before: Record<string, unknown>): string {
  switch (type) {
    case 'aws_bedrock_model_invocation_logging_configuration': {
      const bucketName =
        (getNestedValue(before, 'logging_config.s3_config.bucket_name') as string | undefined) ??
        (getNestedValue(
          before,
          'logging_config.cloudwatch_config.log_group_name',
        ) as string | undefined);
      const dest = bucketName ? ` to ${bucketName}` : '';
      return `${address} is scheduled for destruction; this plan will eliminate Bedrock invocation logging${dest}.`;
    }
    case 'aws_s3_bucket_server_side_encryption_configuration':
      return `Encryption configuration ${address} is scheduled for destruction; the log bucket will fall back to the default (SSE-S3 / AES256), losing per-call KMS Decrypt audit events.`;
    case 'aws_cloudwatch_log_metric_filter':
      return `Metric filter ${address} is scheduled for destruction; an Article 12 monitoring signal will be removed.`;
    case 'aws_cloudwatch_metric_alarm':
      return `Metric alarm ${address} is scheduled for destruction; an Article 12 monitoring signal will be removed.`;
    default:
      return `${address} is scheduled for destruction.`;
  }
}

function remediationFor(type: string): string {
  switch (type) {
    case 'aws_bedrock_model_invocation_logging_configuration':
      return 'Article 12(1) mandates automatic recording of events throughout the AI system\'s operational lifetime. Re-add the resource or migrate logging to a replacement stack before applying.';
    case 'aws_s3_bucket_server_side_encryption_configuration':
      return 'Re-declare KMS encryption (sse_algorithm = "aws:kms" or "aws:kms:dsse") before applying so per-call Decrypt events remain in the audit trail.';
    case 'aws_cloudwatch_log_metric_filter':
    case 'aws_cloudwatch_metric_alarm':
      return 'Restore the monitoring resource or migrate the alert to a replacement before applying. Article 72 post-market monitoring relies on continuous signals.';
    default:
      return 'Restore the resource before applying.';
  }
}

function isLogBucket(
  bucket: string | undefined,
  resourceName: string,
  context: ScanContext,
): boolean {
  if (context.logBucketNames.length === 0) return false;
  if (bucket && context.logBucketNames.includes(bucket)) return true;
  if (context.logBucketNames.includes(resourceName)) return true;
  if (context.logBucketNames.includes(`aws_s3_bucket.${resourceName}`)) return true;
  return false;
}

function isLogGroup(
  name: string | undefined,
  resourceName: string,
  context: ScanContext,
): boolean {
  if (context.logGroupNames.length === 0) return false;
  if (name && context.logGroupNames.includes(name)) return true;
  if (context.logGroupNames.includes(resourceName)) return true;
  if (context.logGroupNames.includes(`aws_cloudwatch_log_group.${resourceName}`)) return true;
  return false;
}
