import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved } from '../utils/resource-helpers';
import { isUnresolvedScalar } from '../utils/literal';

const MIN_RETENTION_DAYS = 180;
const RECOMMENDED_RETENTION_DAYS = 365;

// Same rationale as cw-retention.ts - kept inline rather than imported because
// the lifecycle and log-group thresholds are deliberately decoupled (one could
// be loosened without the other).
const RETENTION_RATIONALE =
  'EU AI Act Art. 19(1) requires high-risk-system logs be kept "for a period ' +
  'appropriate to the intended purpose ... of at least six months" - that six-month ' +
  'minimum is the 180-day floor. Bias drift, hallucinated decisions, and ' +
  'downstream-deployer audits surface months after the event, so sub-180-day ' +
  'retention undermines post-market monitoring (Article 72) and incident ' +
  'investigation; 365 days is the typical floor for production AI.';

export const s3LifecycleRule: ScanRule = {
  id: 'S-12.1.2b',
  description: 'S3 log bucket must have lifecycle retention of at least 180 days',
  severity: 'FAIL',
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
          description: 'No Bedrock logging detected. S3 lifecycle check skipped.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const ref of context.unresolvedBucketRefs) {
      findings.push(inconclusiveFromUnresolved(this, ref, 'bucket'));
    }

    if (context.logBucketNames.length === 0 && context.unresolvedBucketRefs.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'Bedrock logging does not use S3. Skipping S3 lifecycle check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const lifecycleConfigs = findResources(
      files,
      'aws_s3_bucket_lifecycle_configuration',
      context.planOverlay,
    );

    for (const bucketName of context.logBucketNames) {
      const matching = lifecycleConfigs.find((lc) =>
        matchesBucket(lc.body, lc.name, [bucketName], files, context.planOverlay)
      );

      if (!matching) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `No aws_s3_bucket_lifecycle_configuration found for log bucket "${bucketName}". Without a lifecycle policy, retention is governed only by manual deletion - there is no enforced minimum.`,
          remediation:
            `Add an aws_s3_bucket_lifecycle_configuration for "${bucketName}" with ` +
            `an expiration rule of >= ${MIN_RETENTION_DAYS} days ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}). Why: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
        continue;
      }

      const line = findResourceLine(matching.rawHcl, 'aws_s3_bucket_lifecycle_configuration', matching.name);

      // Check lifecycle rules for expiration days
      const rules = getNestedValue(matching.body, 'rule');
      const rulesArray = Array.isArray(rules) ? rules : rules ? [rules] : [];

      let maxDays = 0;
      let sawUnresolvedDays = false;
      for (const rule of rulesArray) {
        if (typeof rule !== 'object' || rule === null) continue;
        const days = getNestedValue(rule, 'expiration.days');
        if (typeof days === 'number' && days > maxDays) {
          maxDays = days;
        } else if (isUnresolvedScalar(days)) {
          sawUnresolvedDays = true;
        }
      }

      // Any expiration.days driven by a var/local/data/module reference means
      // we can't compare against the threshold. If no literal day count beat
      // the threshold and at least one rule was expression-driven, surface
      // INCONCLUSIVE rather than falling through to the "no expiration" FAIL.
      if (sawUnresolvedDays && maxDays < MIN_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'INCONCLUSIVE',
          filePath: matching.filePath,
          line,
          description: `Lifecycle configuration for bucket "${bucketName}" has at least one expiration.days set to a non-literal expression; the scanner cannot determine whether retention meets the ${MIN_RETENTION_DAYS}-day floor.`,
          remediation:
            `Inline a literal expiration.days >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}) on at least one rule, or rerun the ` +
            `scan against terraform plan output where references are resolved.`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
        continue;
      }

      if (maxDays === 0) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Lifecycle configuration for bucket "${bucketName}" has no expiration.days set on any rule - objects will be retained indefinitely or transitioned without bound.`,
          remediation:
            `Set expiration.days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}) on at least one rule. ` +
            `Why: ${RETENTION_RATIONALE} An unbounded lifecycle leaves you exposed to ` +
            `storage cost surprises without giving compliance teams a documented retention floor.`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else if (maxDays < MIN_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days, below the ${MIN_RETENTION_DAYS}-day floor infrarails applies for high-risk AI logging.`,
          remediation:
            `Increase expiration.days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}). Why: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else if (maxDays < RECOMMENDED_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days. infrarails recommends >= ${RECOMMENDED_RETENTION_DAYS} days for production AI workloads.`,
          remediation:
            `Consider increasing expiration.days to ${RECOMMENDED_RETENTION_DAYS}. ` +
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
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days.`,
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
