export type FindingStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP' | 'INCONCLUSIVE';

// One labeled supporting observation attached to a Finding. Lets a rule keep
// the headline `description` to a single verdict and hand the secondary
// context (what is still enforcing, what is not configured, etc.) to the
// formatters as discrete rows instead of one run-on paragraph.
export interface FindingDetail {
  label: string;
  text: string;
}

export interface Finding {
  ruleId: string;
  status: FindingStatus;
  filePath: string;
  line?: number;
  description: string;
  remediation: string;
  // Optional structured detail rendered beneath the headline `description`.
  // `context` holds labeled supporting observations; `scopeNote` carries the
  // "what this rule does / does not see" caveat. Both optional, so rules that
  // need only a one-line description (and the JSON/SARIF emitters) are
  // unaffected.
  context?: FindingDetail[];
  scopeNote?: string;
  regulatoryReference: string;
  nistReference?: string;
  isoReference?: string;
  // Set when an INCONCLUSIVE finding is driven by an unresolvable expression.
  // Carried on the Finding so the strict-mode post-processor in runScan can
  // decide whether the reason is escalatable to FAIL (most are) or genuinely
  // unknowable (plan-known-after-apply, plan-sensitive-redacted).
  unresolvedReason?: UnresolvableReason;
}

export interface ScanRule {
  id: string;
  description: string;
  severity: 'FAIL' | 'WARN';
  regulatoryReference: string;
  nistReference?: string;
  isoReference?: string;
  phase1?: boolean;
  run(files: ParsedFile[], context: ScanContext): Finding[];
}

export type UnresolvableReason =
  | 'var-no-default'
  | 'local-not-literal'
  | 'data-source-ssm'
  | 'data-source-other'
  | 'module-output'
  | 'complex-interpolation'
  | 'unknown-format'
  | 'plan-known-after-apply'
  | 'plan-sensitive-redacted'
  | 'plan-deferred-data-source'
  | 'plan-remote-state-unreachable'
  | 'plan-instances-divergent'
  // CloudFormation-specific reasons. Produced by the CFN normaliser's sentinel
  // expressions (src/cfn/intrinsics.ts) and by the Condition handling; none of
  // them are escalatable under --plan --strict-account-logging because the
  // plan overlay is Terraform-only and cannot resolve them.
  | 'cfn-import-value'
  | 'cfn-dynamic-reference'
  | 'cfn-pseudo-parameter'
  | 'cfn-fn-not-static'
  | 'cfn-condition-gated';

export interface UnresolvedRef {
  expression: string;
  reason: UnresolvableReason;
  sourceField: string;
}

export type ResolutionResult =
  | { kind: 'literal'; value: string }
  | { kind: 'address'; value: string; resourceType: string; resourceName: string }
  | { kind: 'unresolvable'; expression: string; reason: UnresolvableReason; sourceField: string };

export interface PlanResource {
  address: string;
  type: string;
  name: string;
  values: Record<string, unknown>;
  unknownPaths: Set<string>;
  sensitivePaths: Set<string>;
}

export interface PlanDeletion {
  address: string;
  type: string;
  name: string;
  before: Record<string, unknown>;
  replaceWithCreate: boolean;
}

export interface PlanOverlay {
  formatVersion: string;
  terraformVersion: string;
  // First-instance-by-normalised-key (legacy / convenience): one entry per
  // unique "<type>.<name>", losing per-instance detail for count/for_each.
  // Kept for backward-compatibility with callers that only need a summary.
  // For per-instance accuracy, use `instancesByNormalised`.
  resources: Map<string, PlanResource>;
  // All plan instances grouped by normalised "<type>.<name>" key. For a
  // resource with `count = 3`, this list has 3 PlanResource entries with
  // distinct `address` (e.g. `aws_s3_bucket.logs[0]`, `[1]`, `[2]`).
  // `after_unknown` / `after_sensitive` from resource_changes are attached
  // to the matching instance by full address, so unknowns in instance [1]
  // do not bleed into instance [0]'s safety filters.
  instancesByNormalised: Map<string, PlanResource[]>;
  deletions: Map<string, PlanDeletion>;
  flags: { noActionableChanges: boolean };
  variables: Map<string, string | number | boolean>;
  // Scalar outputs from `planned_values.child_modules[].outputs`, keyed by the
  // expression form Terraform uses to reference them: `module.<path>.<name>`,
  // with `[...]` index segments stripped so refs to count/for_each modules
  // resolve regardless of which instance the expression names.
  outputs: Map<string, { value: string | number | boolean; sensitive: boolean }>;
  // Reference (not value) graph extracted from the plan `configuration` block.
  // Lets a resource attribute be traced to a terminal resource address across
  // module boundaries even when the wired value is known-after-apply (so it
  // survives where `outputs` - which only carries known scalars - cannot).
  // Optional: absent on overlays built without the configuration block (older
  // fixtures, plans produced without it) - callers must tolerate undefined.
  configReferences?: ConfigReferenceGraph;
}

// A reference graph distilled from the plan `configuration` block. Every value
// is a *qualified reference node* in one of three string-tagged forms:
//   res:<type>.<name>            - a terminal resource (leaf address, no attr)
//   out:module.<full-path>.<out> - a module output, resolvable via `moduleOutputs`
//   var:<module-full-path>::<n>  - a module input variable, resolvable via `varBindings`
// (module-full-path is "" for the root module). Edges are pre-qualified at parse
// time so a consumer can walk them without re-deriving module scope.
export interface ConfigReferenceGraph {
  // '<normalised-resource-address>#<top-level-attribute>' -> qualified ref nodes
  // reachable from that attribute's expression.
  resourceAttrs: Map<string, string[]>;
  // 'module.<full-path>.<output-name>' -> qualified ref nodes the output returns.
  moduleOutputs: Map<string, string[]>;
  // '<child-module-full-path>::<input-name>' -> qualified ref nodes bound at the
  // call site (in the parent module's scope).
  varBindings: Map<string, string[]>;
}

export interface ScanContext {
  bedrockLoggingDetected: boolean;
  logBucketNames: string[];
  logGroupNames: string[];
  unresolvedBucketRefs: UnresolvedRef[];
  unresolvedGroupRefs: UnresolvedRef[];
  // When false (default), S-12.1.1 returns INCONCLUSIVE for "Bedrock used but no
  // logging config in scanned files" - most enterprises put the logging config
  // in a separate account-baseline stack and a hard FAIL is wrong. When true,
  // the scanner is told the entire infra estate is in scope and missing logging
  // is a real FAIL.
  strictAccountLogging: boolean;
  // Plan overlay (from `terraform show -json`) used by rules and the resolver
  // to elevate INCONCLUSIVE findings to PASS/FAIL and to surface resources
  // buried inside remote modules. Undefined when --plan was not supplied.
  planOverlay?: PlanOverlay;
}

export interface ParsedFile {
  filePath: string;
  json: HCL2JSONOutput;
  rawHcl: string;
}

export interface HCL2JSONOutput {
  resource?: Record<string, Record<string, Record<string, unknown>[]>>;
  data?: Record<string, Record<string, Record<string, unknown>[]>>;
  variable?: Record<string, Record<string, unknown>[]>;
  locals?: Record<string, unknown>[];
  module?: Record<string, Array<Record<string, unknown>>>;
  [key: string]: unknown;
}
