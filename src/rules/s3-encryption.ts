import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved } from '../utils/resource-helpers';

export const s3EncryptionRule: ScanRule = {
  id: 'S-12.x.2a',
  description: 'S3 log bucket must use KMS encryption',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 15(5) - cybersecurity, incl. resilience to confidentiality attacks (KMS protects log confidentiality at rest); Article 12(2) - traceability of access to AI system logs (KMS Decrypt emits per-principal CloudTrail audit events)',
  nistReference: 'NIST AI RMF 1.0: MEASURE 2.7 (security and resilience); MEASURE 2.10 (privacy of AI system data)',
  isoReference: 'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.7.4 (Quality of data - integrity protection)',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. S3 encryption check skipped.',
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
          description: 'Bedrock logging does not use S3. Skipping S3 encryption check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const encryptionConfigs = findResources(
      files,
      'aws_s3_bucket_server_side_encryption_configuration',
      context.planOverlay,
    );

    for (const bucketName of context.logBucketNames) {
      const matching = encryptionConfigs.find((ec) =>
        matchesBucket(ec.body, ec.name, [bucketName], files, context.planOverlay)
      );

      if (!matching) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `No aws_s3_bucket_server_side_encryption_configuration found for log bucket "${bucketName}". Encryption posture falls back to the bucket default (SSE-S3 / AES256), which is invisible to per-call audit.`,
          remediation:
            'Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = ' +
            '"aws:kms" or "aws:kms:dsse". ' +
            'Why KMS specifically: SSE-S3 (AES256) encrypts at rest but does not emit per-call ' +
            'CloudTrail Decrypt events - every read of your AI logs is invisible to the audit ' +
            'trail. KMS-encrypted reads emit Decrypt events with the principal, which is exactly ' +
            'what Article 12 requires for downstream-deployer access traceability. ' +
            'aws:kms:dsse adds dual-layer defense-in-depth at modest cost.',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
        continue;
      }

      const line = findResourceLine(matching.rawHcl, 'aws_s3_bucket_server_side_encryption_configuration', matching.name);

      // Navigate to the SSE algorithm
      const sseAlgorithm = getNestedValue(
        matching.body,
        'rule.apply_server_side_encryption_by_default.sse_algorithm'
      );

      if (sseAlgorithm === 'aws:kms' || sseAlgorithm === 'aws:kms:dsse') {
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: matching.filePath,
          line,
          description: `Log bucket "${bucketName}" uses ${sseAlgorithm} encryption.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Log bucket "${bucketName}" uses "${sseAlgorithm || 'no'}" encryption instead of KMS - log access is encrypted at rest but is not auditable per-call.`,
          remediation:
            'Set sse_algorithm to "aws:kms" or "aws:kms:dsse" in the encryption configuration. ' +
            'Why: AES256 (SSE-S3) does not emit CloudTrail Decrypt events, so reads of AI logs ' +
            'are invisible to your audit trail. KMS Decrypt events name the principal who read ' +
            'the data - Article 12 requires this level of traceability for downstream-deployer access.',
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      }
    }

    return findings;
  },
};
