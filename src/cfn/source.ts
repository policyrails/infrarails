// ---------------------------------------------------------------------------
// Source-dialect helpers shared by the normaliser, rules, and formatter.
// ---------------------------------------------------------------------------

/**
 * Reserved key the CFN normaliser stamps on every synthesized resource body
 * whose CloudFormation resource is guarded by a Condition. Rules treat a
 * stamped resource as "may not exist at deploy time" -> INCONCLUSIVE
 * (cfn-condition-gated) instead of trusting its properties.
 */
export const CFN_CONDITION_KEY = '__cfn_condition';

/**
 * Condition name stamped on a synthesized CFN resource body, or undefined for
 * Terraform-sourced (and unconditional CFN) resources.
 */
export function cfnConditionOf(body: Record<string, unknown> | undefined): string | undefined {
  if (!body) return undefined;
  const v = body[CFN_CONDITION_KEY];
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/**
 * True when a finding/resource file path points at a CloudFormation template.
 * Terraform paths (.tf, .tf.json), plan-sourced citations (plan:<address>),
 * and empty paths are not CFN.
 */
export function isCfnTemplatePath(filePath: string): boolean {
  if (!filePath || filePath.startsWith('plan:')) return false;
  if (filePath.endsWith('.tf') || filePath.endsWith('.tf.json')) return false;
  return filePath.endsWith('.yaml') || filePath.endsWith('.yml') || filePath.endsWith('.json');
}

/** Dialect of a finding's file path, for the mixed-report source chip. */
export function sourceOfPath(filePath: string): 'terraform' | 'cloudformation' | undefined {
  if (!filePath) return undefined;
  if (isCfnTemplatePath(filePath)) return 'cloudformation';
  return 'terraform';
}
