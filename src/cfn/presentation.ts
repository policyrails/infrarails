import { Finding } from '../types';
import { CFN_REF_TYPE_MAP } from './normalise';
import { sourceOfPath } from './source';

// ---------------------------------------------------------------------------
// CFN-dialect presentation of findings.
//
// The pipeline's internal representation is the Terraform-JSON shape, so rule
// messages are composed in TF vocabulary ("aws_bedrock_guardrail.GR", "set
// input_strength"). For a finding whose source is a CloudFormation template
// that vocabulary is alien - the user wrote AWS::Bedrock::Guardrail and
// InputStrength. This module rewrites the *user-facing text* (description,
// remediation) of CFN-sourced findings into CFN vocabulary at the rendering
// edge. The Finding objects rules produce, and everything tests assert on via
// runScan, stay canonical TF-shaped; only the CLI output is translated.
//
// Deliberate non-goals:
//  - Raw expression strings (`${aws_bedrock_guardrail.GR.guardrail_arn}`) are
//    diagnostic values echoed verbatim - a type name immediately followed by
//    `.` and a further attribute segment is part of such a chain and is left
//    untouched rather than half-translated.
//  - TF-only advice stays TF: aws_bedrock_model_invocation_logging_configuration
//    has no CFN equivalent (that is the point of the finding citing it), so it
//    is absent from the map below and never rewritten.
// ---------------------------------------------------------------------------

/**
 * TF type -> CFN-facing display name. Inverse of CFN_REF_TYPE_MAP plus the
 * synthesized resources the normaliser fabricates from inline CFN property
 * blocks (S3 companions, IAM inline policies), which display as the property
 * block on their parent type.
 */
const TF_TO_CFN_DISPLAY: Record<string, string> = {
  ...Object.fromEntries(Object.entries(CFN_REF_TYPE_MAP).map(([cfn, tf]) => [tf, cfn])),
  aws_iam_role_policy: 'AWS::IAM::Policy',
  aws_s3_bucket_server_side_encryption_configuration: 'AWS::S3::Bucket BucketEncryption',
  aws_s3_bucket_versioning: 'AWS::S3::Bucket VersioningConfiguration',
  aws_s3_bucket_lifecycle_configuration: 'AWS::S3::Bucket LifecycleConfiguration',
  aws_s3_bucket_object_lock_configuration: 'AWS::S3::Bucket ObjectLockConfiguration',
};

/**
 * snake_case property terms that appear in rule messages -> the CFN property
 * name. Curated (not a generic snake->Pascal pass) so genuinely TF-flavoured
 * advice is never mangled. `_` is a word character, so the \b guards keep
 * e.g. `guardrail_version` from matching inside a longer identifier.
 */
const TF_TO_CFN_TERMS: Record<string, string> = {
  guardrail_configuration: 'GuardrailConfiguration',
  guardrail_identifier: 'GuardrailIdentifier',
  guardrail_version: 'GuardrailVersion',
  input_strength: 'InputStrength',
  output_strength: 'OutputStrength',
  retention_in_days: 'RetentionInDays',
};

// Longest-first so aws_bedrock_guardrail_version is consumed before its
// aws_bedrock_guardrail prefix, aws_s3_bucket_versioning before aws_s3_bucket.
const TYPES_LONGEST_FIRST = Object.keys(TF_TO_CFN_DISPLAY).sort((a, b) => b.length - a.length);

// `<tf_type>.<Name>` not followed by another `.<segment>` (an expression
// chain) -> `<CFN::Type> "Name"`. Name shape covers CFN logical ids and TF
// resource names.
const ADDRESS_RE = new RegExp(
  `\\b(${TYPES_LONGEST_FIRST.join('|')})\\.([A-Za-z_][A-Za-z0-9_-]*)(?!\\.?[A-Za-z0-9_-])`,
  'g',
);

// A bare type mention ("1 aws_bedrock_guardrail resource(s)"). The (?!\.)
// guard leaves `${type.name.attr}` expression chains fully intact.
const BARE_TYPE_RE = new RegExp(`\\b(${TYPES_LONGEST_FIRST.join('|')})\\b(?!\\.)`, 'g');

const TERM_RES = Object.entries(TF_TO_CFN_TERMS).map(
  ([tf, cfn]) => [new RegExp(`\\b${tf}\\b`, 'g'), cfn] as const,
);

/** Rewrite one message string from TF vocabulary to CFN vocabulary. */
export function rewriteToCfnVocabulary(text: string): string {
  if (!text) return text;
  let out = text.replace(ADDRESS_RE, (_m, tfType: string, name: string) => {
    return `${TF_TO_CFN_DISPLAY[tfType]} "${name}"`;
  });
  out = out.replace(BARE_TYPE_RE, (m, tfType: string) => TF_TO_CFN_DISPLAY[tfType] ?? m);
  for (const [re, cfn] of TERM_RES) out = out.replace(re, cfn);
  return out;
}

/**
 * Rewrite the user-facing text of CFN-sourced findings into CFN vocabulary.
 *
 * A finding counts as CFN-sourced when its filePath points at a template; an
 * estate-level finding with no path (e.g. "no guardrail declared anywhere")
 * follows the scan as a whole and is rewritten only when *every* scanned file
 * is a CFN template. In a mixed estate the TF-shaped canonical vocabulary
 * stands for pathless findings - it is the lingua franca both dialects map to.
 */
export function applyCfnPresentation(findings: Finding[], scannedFilePaths: string[]): Finding[] {
  const allCfn =
    scannedFilePaths.length > 0 &&
    scannedFilePaths.every((p) => sourceOfPath(p) === 'cloudformation');

  return findings.map((f) => {
    const isCfn = f.filePath ? sourceOfPath(f.filePath) === 'cloudformation' : allCfn;
    if (!isCfn) return f;
    return {
      ...f,
      description: rewriteToCfnVocabulary(f.description),
      remediation: rewriteToCfnVocabulary(f.remediation),
    };
  });
}
