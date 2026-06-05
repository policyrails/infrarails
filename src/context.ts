import { ParsedFile, PlanOverlay, ScanContext, UnresolvedRef } from './types';
import { FoundResource, findResources, getNestedValue } from './utils/resource-helpers';
import { resolveOrPlanFallback } from './resolver';

/**
 * Build a ScanContext by extracting log bucket and log group names
 * from aws_bedrock_model_invocation_logging_configuration resources.
 *
 * Resolved refs (literals + addresses) populate logBucketNames / logGroupNames.
 * Unresolvable refs (var-no-default, SSM, module output, complex interpolation, ...)
 * populate unresolvedBucketRefs / unresolvedGroupRefs so dependent rules can emit
 * INCONCLUSIVE findings instead of silently skipping.
 *
 * When `overlay` is supplied, plan-resolved values fill in any ref the static
 * resolver gives up on (containing-resource fallback). Logging configs are
 * additionally discovered from the overlay so remote-module-buried
 * configurations are evaluated by the same rules.
 */
export interface BuildContextOptions {
  strictAccountLogging?: boolean;
  overlay?: PlanOverlay;
}

export function buildScanContext(files: ParsedFile[], options: BuildContextOptions = {}): ScanContext {
  const overlay = options.overlay;
  const context: ScanContext = {
    bedrockLoggingDetected: false,
    logBucketNames: [],
    logGroupNames: [],
    unresolvedBucketRefs: [],
    unresolvedGroupRefs: [],
    strictAccountLogging: options.strictAccountLogging ?? false,
    planOverlay: overlay,
  };

  const loggingConfigs = findResources(
    files,
    'aws_bedrock_model_invocation_logging_configuration',
    overlay,
  );
  if (loggingConfigs.length === 0) return context;

  context.bedrockLoggingDetected = true;

  for (const config of loggingConfigs) {
    const containingAddress =
      config.source === 'plan' && config.address
        ? config.address.replace(/^module\.[^.]+(?:\.module\.[^.]+)*\./, '')
        : `aws_bedrock_model_invocation_logging_configuration.${config.name}`;
    extractRef(
      config,
      'logging_config.s3_config.bucket_name',
      files,
      context,
      'bucket',
      containingAddress,
      overlay,
    );
    extractRef(
      config,
      'logging_config.cloudwatch_config.log_group_name',
      files,
      context,
      'group',
      containingAddress,
      overlay,
    );
    extractRef(
      config,
      'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      files,
      context,
      'bucket',
      containingAddress,
      overlay,
    );
  }

  context.logBucketNames = [...new Set(context.logBucketNames)];
  context.logGroupNames = [...new Set(context.logGroupNames)];
  context.unresolvedBucketRefs = dedupeUnresolved(context.unresolvedBucketRefs);
  context.unresolvedGroupRefs = dedupeUnresolved(context.unresolvedGroupRefs);

  return context;
}

function extractRef(
  config: FoundResource,
  attributePath: string,
  files: ParsedFile[],
  context: ScanContext,
  kind: 'bucket' | 'group',
  containingAddress: string,
  overlay?: PlanOverlay,
): void {
  let ref = getNestedValue(config.body, attributePath);
  let sourceFilePath = config.source === 'hcl' ? config.filePath : undefined;
  let planLiteral = config.source === 'plan';

  // A plan-sourced config buried in a local module can omit an attribute the
  // plan marked computed-at-apply-time - e.g. an s3_config.bucket_name built
  // from the account id is dropped from planned_values entirely. The on-disk
  // HCL block (folded in by findResources) still carries the reference that
  // names the bucket / log-group resource, so anchor on it: resolveExpression
  // recovers the resource address even though the plan can't resolve the literal
  // name yet. Without this we would wrongly conclude the logging sink is absent.
  // Terraform represents a dropped computed-at-apply attribute either by
  // omitting it (undefined) or emitting it as null - treat both as "absent".
  if ((ref === undefined || ref === null) && config.hclBody) {
    const hclRef = getNestedValue(config.hclBody, attributePath);
    if (hclRef !== undefined && hclRef !== null) {
      ref = hclRef;
      sourceFilePath = config.filePath; // the fold copied the HCL file path
      planLiteral = false; // hclRef is an HCL expression - resolve it, don't take it literally
    }
  }

  if (ref === undefined || ref === null) return;

  // Plan-sourced configs carry already-resolved literal values rather than
  // HCL expressions. Skip the resolver and use the value directly.
  if (planLiteral && typeof ref === 'string' && !ref.includes('${')) {
    if (kind === 'bucket') context.logBucketNames.push(ref);
    else context.logGroupNames.push(ref);
    return;
  }

  const result = resolveOrPlanFallback(
    ref,
    containingAddress,
    attributePath,
    files,
    attributePath,
    sourceFilePath,
    overlay,
  );
  if (!result) return;
  if (result.kind === 'literal' || result.kind === 'address') {
    if (kind === 'bucket') context.logBucketNames.push(result.value);
    else context.logGroupNames.push(result.value);
  } else {
    const target = kind === 'bucket' ? context.unresolvedBucketRefs : context.unresolvedGroupRefs;
    target.push({
      expression: result.expression,
      reason: result.reason,
      sourceField: result.sourceField,
    });
  }
}

function dedupeUnresolved(refs: UnresolvedRef[]): UnresolvedRef[] {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = `${r.expression}|${r.reason}|${r.sourceField}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
