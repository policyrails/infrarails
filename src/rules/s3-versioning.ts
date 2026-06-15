import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved, cfnConditionOf, inconclusiveConditional } from '../utils/resource-helpers';

export const s3VersioningRule: ScanRule = {
  id: 'S-12.x.1',
  description: 'S3 log bucket must have versioning or Object Lock enabled',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 19(1) - Logs must be kept intact for at least six months (versioning/Object Lock preserves them against silent overwrite or deletion); Article 15(5) - resilience against unauthorised alteration of system outputs',
  nistReference: 'NIST AI RMF 1.0: MEASURE 2.7 (security and resilience); MANAGE 4.3 (incident response evidence preservation)',
  isoReference: 'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs - integrity); A.6.2.4 (AI system verification and validation)',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. S3 versioning check skipped.',
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
          description: 'Bedrock logging does not use S3. Skipping S3 versioning check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const versioningConfigs = findResources(
      files,
      'aws_s3_bucket_versioning',
      context.planOverlay,
    );
    const objectLockConfigs = findResources(
      files,
      'aws_s3_bucket_object_lock_configuration',
      context.planOverlay,
    );

    for (const bucketName of context.logBucketNames) {
      // Check versioning
      const versioningMatch = versioningConfigs.find((vc) =>
        matchesBucket(vc.body, vc.name, [bucketName], files, context.planOverlay)
      );

      const hasVersioning = versioningMatch &&
        getNestedValue(versioningMatch.body, 'versioning_configuration.status') === 'Enabled';

      // Check Object Lock
      const objectLockMatch = objectLockConfigs.find((ol) =>
        matchesBucket(ol.body, ol.name, [bucketName], files, context.planOverlay)
      );

      const hasObjectLock = !!objectLockMatch;

      // A Condition-guarded CFN control cannot firmly satisfy the check: it
      // may not exist at deploy time. PASS only on an unconditional control;
      // when the only satisfying control is conditional -> INCONCLUSIVE.
      const versioningFirm = hasVersioning && !cfnConditionOf(versioningMatch!.body);
      const objectLockFirm = hasObjectLock && !cfnConditionOf(objectLockMatch!.body);
      if ((hasVersioning || hasObjectLock) && !versioningFirm && !objectLockFirm) {
        const conditionalResource = hasVersioning ? versioningMatch! : objectLockMatch!;
        const conditionalType = hasVersioning
          ? 'aws_s3_bucket_versioning'
          : 'aws_s3_bucket_object_lock_configuration';
        findings.push(
          inconclusiveConditional(this, {
            label: `${hasVersioning ? 'Versioning' : 'Object Lock'} configuration for log bucket "${bucketName}"`,
            condition: cfnConditionOf(conditionalResource.body)!,
            filePath: conditionalResource.filePath,
            line: findResourceLine(conditionalResource.rawHcl, conditionalType, conditionalResource.name),
          }),
        );
        continue;
      }

      if (versioningFirm || objectLockFirm) {
        const resource = (versioningFirm ? versioningMatch : objectLockMatch)!;
        const resourceType = versioningFirm ? 'aws_s3_bucket_versioning' : 'aws_s3_bucket_object_lock_configuration';
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: resource.filePath,
          line: findResourceLine(resource.rawHcl, resourceType, resource.name),
          description: `Log bucket "${bucketName}" has ${versioningFirm ? 'versioning' : 'Object Lock'} enabled.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `Log bucket "${bucketName}" has neither versioning nor Object Lock enabled - a same-key PUT or a DeleteObject call will silently overwrite or remove log entries with no recoverable history.`,
          remediation:
            'Add aws_s3_bucket_versioning with versioning_configuration.status = "Enabled", ' +
            'or aws_s3_bucket_object_lock_configuration. ' +
            'Why: Article 12 requires log integrity sufficient for downstream auditability. ' +
            'Without versioning, an attacker (or a script bug) can overwrite a log object ' +
            'using the same key and erase forensic evidence - by the time you notice, the ' +
            'original is gone. Best practice for high-risk AI is Object Lock in COMPLIANCE ' +
            'mode (immutable for the retention period); versioning + a bucket policy that ' +
            'denies s3:DeleteObject is acceptable for lower-risk systems.',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      }
    }

    return findings;
  },
};
