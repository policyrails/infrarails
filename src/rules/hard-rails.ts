import { ScanRule, Finding, ParsedFile, ScanContext, UnresolvableReason, PlanOverlay } from '../types';
import { findResources, findResourceLine, getNestedValue, FoundResource, cfnConditionOf, inconclusiveConditional } from '../utils/resource-helpers';
import { isUnresolvedScalar } from '../utils/literal';
import { resolveExpression } from '../resolver';
import { buildGuardrailGraph } from '../utils/guardrail-graph';

// ---------------------------------------------------------------------------
// S-9.x.3 - hard-rails enforcement. The third rule in the guardrail
// progression: S-9.x.2 (presence) -> S-9.x.1 (attachment) -> S-9.x.3 (body).
// S-9.x.1/2 confirm a guardrail is attached and declared; neither inspects the
// guardrail *body*. A Bedrock Agent can pass both rules while the attached
// guardrail has NONE actions everywhere - a guardrail in name only. This rule
// inspects each aws_bedrock_guardrail body and reports whether the two
// MANDATORY enforcement surfaces (a PROMPT_ATTACK prompt-injection filter and a
// harmful-content filter) actually block, with PII, contextual grounding, and
// denied topics scored as supporting context.
//
// Negative space - what S-9.x.3 deliberately does NOT verify (design doc §8):
//   - SDK-layer enforcement (InvokeModel/Converse guardrailIdentifier) - that
//     is application code, not Terraform.
//   - Whether specific denied-topic names are correct for the workload.
//   - Threshold magnitude beyond > 0 (whether 0.5 is "enough" is app judgement).
//   - Cross-checks against EU AI Act Annex III high-risk categorisation.
//   - Guardrails from non-AWS vendors (Azure Content Safety, OpenAI Moderation,
//     Lakera, Guardrails-AI, NeMo, etc.). The rule's scope is AWS Bedrock
//     Guardrails only.
//   - PII/grounding *absence* is never a gap: PII is commonly handled upstream
//     (Macie, Comprehend, DLP proxy) and grounding only applies to RAG.
// ---------------------------------------------------------------------------

const REGULATORY_REFERENCE =
  'EU AI Act Art. 9(2)(d) (appropriate and targeted risk management measures - ' +
  'applies where the system is high-risk under Art. 6/Annex III); ' +
  'Art. 9(5)(b) (adequate mitigation and control measures for risks that cannot ' +
  'be eliminated by design); ' +
  'Art. 15(4) (resilience to errors and inconsistencies - anchors the contextual ' +
  'grounding surface, i.e. hallucination resistance); ' +
  'Art. 15(5) ¶3 (adversarial examples / model evasion and confidentiality attacks ' +
  '- PROMPT_ATTACK filter and PII BLOCK respectively)';

const NIST_REFERENCE =
  'NIST AI RMF 1.0: ' +
  'MEASURE 2.5 (validity and reliability - contextual grounding check); ' +
  'MEASURE 2.6 (AI system safety - VIOLENCE content filter category and fail-safe ' +
  'behaviour); ' +
  'MEASURE 2.7 (security and resilience - adversarial examples maps to ' +
  'PROMPT_ATTACK filter); ' +
  'MEASURE 2.10 (privacy risk - PII BLOCK on sensitive_information_policy_config)';

const ISO_REFERENCE =
  'ISO/IEC 42001:2023 Annex A: ' +
  'A.6.2.6 (AI system operation and monitoring - guardrails are operational ' +
  'controls applied at inference)';

// Scope note appended to non-PASS remediation so multi-vendor users are not
// misled into reading a clean S-9.x.3 as covering their entire safety stack.
const VENDOR_SCOPE_NOTE =
  'Scope: this rule inspects AWS Bedrock Guardrail bodies only. It does not see ' +
  'non-AWS guardrail vendors or SDK-layer (InvokeModel/Converse) enforcement.';

const UNATTACHED_NOTE =
  ' Not attached to any Bedrock Agent in the scanned IaC; if used via SDK ' +
  'InvokeModel/Converse this is expected and not verifiable here.';

// PROMPT_ATTACK accepts LOW as blocking (any non-NONE strength is a real
// injection control); harmful-content filters require MEDIUM+ to count as
// enforcing. This asymmetry is intentional - see design doc §1.
const PROMPT_ATTACK_BLOCKING = new Set(['LOW', 'MEDIUM', 'HIGH']);
const CONTENT_BLOCKING = new Set(['MEDIUM', 'HIGH']);

// Top-level guardrail policy blocks. Used only for the "empty guardrail" check;
// word_policy_config is included (a guardrail with only word filters is not
// "empty") even though word filters are out of scope for classification.
const POLICY_BLOCKS = [
  'content_policy_config',
  'topic_policy_config',
  'sensitive_information_policy_config',
  'contextual_grounding_policy_config',
  'word_policy_config',
] as const;

type SurfaceState = 'BLOCKING' | 'PERMISSIVE' | 'ABSENT' | 'INCONCLUSIVE';

interface SurfaceResult {
  state: SurfaceState;
  weakReasons: string[];
  // Set only when state === 'INCONCLUSIVE'. Carries the first unresolved reason
  // so the runner's strict-mode post-processor can escalate it consistently.
  unresolvedReason?: UnresolvableReason;
}

// A guardrail body field that gates a surface's verdict, resolved to one of:
// a concrete literal, an unresolvable expression (var/local/data/module), or
// absent (the field is not declared).
type Decisive =
  | { kind: 'literal'; value: string }
  | { kind: 'unresolvable'; reason: UnresolvableReason }
  | { kind: 'absent' };

export const hardRailsRule: ScanRule = {
  id: 'S-9.x.3',
  description:
    'aws_bedrock_guardrail bodies must enforce both mandatory surfaces: a PROMPT_ATTACK ' +
    'prompt-injection filter and at least one harmful-content filter set to MEDIUM/HIGH ' +
    '(AWS Bedrock Guardrails only - SDK-layer and non-AWS-vendor enforcement out of scope)',
  severity: 'WARN',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    const overlay = context.planOverlay;
    const guardrails = findResources(files, 'aws_bedrock_guardrail', overlay);

    if (guardrails.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description:
            'No aws_bedrock_guardrail declared in scanned IaC. Body inspection ' +
            'skipped - see S-9.x.2 for the presence-layer signal.',
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    const { guardrailToAgents } = buildGuardrailGraph(files, overlay);

    return guardrails.map((gr) =>
      evaluateGuardrail(this, gr, files, overlay, guardrailToAgents.get(gr.name) ?? []),
    );
  },
};

function evaluateGuardrail(
  rule: ScanRule,
  gr: FoundResource,
  files: ParsedFile[],
  overlay: PlanOverlay | undefined,
  attachingAgents: string[],
): Finding {
  // A plan instance folded with its on-disk HCL block carries the HCL raw
  // source (so findResourceLine resolves a line) while keeping source 'plan';
  // key the line off rawHcl, not source. Empty rawHcl (true plan-only) -> none.
  const line = findResourceLine(gr.rawHcl, 'aws_bedrock_guardrail', gr.name);
  const sourceFilePath = gr.source === 'hcl' ? gr.filePath : undefined;
  const body = gr.body;
  const label = guardrailLabel(gr.name, attachingAgents);

  // Condition-guarded CFN guardrail: its body cannot be trusted to exist at
  // deploy time, so body inspection cannot produce a PASS/WARN verdict.
  const condition = cfnConditionOf(body);
  if (condition) {
    return inconclusiveConditional(rule, {
      label,
      condition,
      filePath: gr.filePath,
      line,
    });
  }

  const base = {
    ruleId: rule.id,
    filePath: gr.filePath,
    line,
    regulatoryReference: REGULATORY_REFERENCE,
    nistReference: NIST_REFERENCE,
    isoReference: ISO_REFERENCE,
  };

  // (1) No policy blocks declared at all -> WARN (empty guardrail).
  const hasAnyPolicy = POLICY_BLOCKS.some((b) => getNestedValue(body, b) !== undefined);
  if (!hasAnyPolicy) {
    return {
      ...base,
      status: 'WARN',
      description:
        `${label} declares no policy body - it cannot block, deny, redact, or ground ` +
        `anything.${attachingAgents.length === 0 ? UNATTACHED_NOTE : ''}`,
      remediation: emptyRemediation(),
    };
  }

  const cpc = getNestedValue(body, 'content_policy_config');
  const cpcDynamic = hasDynamicBlock(cpc);
  const filters = blocks(body, 'content_policy_config.filters_config');

  const promptAttack = withDynamic(
    classifyPromptAttack(filters, files, sourceFilePath, overlay),
    cpcDynamic,
  );
  const harmful = withDynamic(
    classifyHarmfulContent(filters, files, sourceFilePath, overlay),
    cpcDynamic,
  );
  const pii = classifyPii(body, files, sourceFilePath, overlay);
  const grounding = classifyGrounding(body, files, sourceFilePath, overlay);
  const denyTopics = countDenyTopics(body);

  // (2) A mandatory surface's decisive value is expression-driven -> INCONCLUSIVE.
  // Conditional-surface INCONCLUSIVE never gates the finding.
  const mandatoryInconclusive =
    promptAttack.state === 'INCONCLUSIVE'
      ? promptAttack
      : harmful.state === 'INCONCLUSIVE'
        ? harmful
        : undefined;
  if (mandatoryInconclusive) {
    const fields = mandatoryInconclusive.weakReasons.join('; ') || 'a mandatory enforcement strength';
    return {
      ...base,
      status: 'INCONCLUSIVE',
      description:
        `${label} declares a mandatory surface whose decisive value is expression-driven ` +
        `(${fields}). Static scanning cannot determine whether it enforces any block at ` +
        `runtime. Rerun with --plan to resolve.`,
      remediation: gapRemediation(),
      unresolvedReason: mandatoryInconclusive.unresolvedReason,
    };
  }

  // (3) Either mandatory surface ABSENT or PERMISSIVE -> WARN (mandatory gap).
  const promptAttackOk = promptAttack.state === 'BLOCKING';
  const harmfulOk = harmful.state === 'BLOCKING';
  if (!promptAttackOk || !harmfulOk) {
    const missing: string[] = [];
    const stillEnforcing: string[] = [];
    if (!promptAttackOk) {
      missing.push(
        promptAttack.state === 'ABSENT'
          ? 'no PROMPT_ATTACK filter - prompt injection uncontrolled'
          : 'PROMPT_ATTACK filter present but not enforcing (input_strength = NONE)',
      );
    } else {
      stillEnforcing.push('the PROMPT_ATTACK prompt-injection filter');
    }
    if (!harmfulOk) {
      missing.push(
        harmful.state === 'ABSENT'
          ? 'no harmful-content filter declared'
          : 'all content filters set below MEDIUM',
      );
    } else {
      stillEnforcing.push('a harmful-content filter (MEDIUM+)');
    }
    return {
      ...base,
      status: 'WARN',
      description:
        `${label} is missing a mandatory control: ${missing.join('; ')}. Attaching this ` +
        `guardrail satisfies S-9.x.1 / S-9.x.2 but leaves the named risk uncontrolled.` +
        (stillEnforcing.length > 0
          ? ` The other mandatory surface is enforcing: ${stillEnforcing.join(' and ')}.`
          : '') +
        conditionalContext(pii, grounding, denyTopics) +
        (attachingAgents.length === 0 ? UNATTACHED_NOTE : ''),
      remediation: gapRemediation(),
    };
  }

  // (4) Both mandatory surfaces BLOCKING -> PASS.
  return {
    ...base,
    status: 'PASS',
    description:
      `${label} enforces both mandatory surfaces (prompt-injection filter + ` +
      `harmful-content filter). The PROMPT_ATTACK filter contributes to adversarial-input ` +
      `resilience but does not catch indirect injection via RAG/tool outputs.` +
      conditionalContext(pii, grounding, denyTopics) +
      (attachingAgents.length === 0 ? UNATTACHED_NOTE : ''),
    remediation: '',
  };
}

// --- surface classifiers ---------------------------------------------------

function classifyPromptAttack(
  filters: Record<string, unknown>[],
  files: ParsedFile[],
  sourceFilePath: string | undefined,
  overlay: PlanOverlay | undefined,
): SurfaceResult {
  const promptFilters = filters.filter((f) => readType(f) === 'PROMPT_ATTACK');
  if (promptFilters.length === 0) return { state: 'ABSENT', weakReasons: [] };

  const weakReasons: string[] = [];
  let unresolved: UnresolvableReason | undefined;
  for (const f of promptFilters) {
    const d = resolveDecisive(f.input_strength, files, sourceFilePath, overlay);
    if (d.kind === 'literal') {
      if (PROMPT_ATTACK_BLOCKING.has(d.value.toUpperCase())) {
        return { state: 'BLOCKING', weakReasons: [] };
      }
      weakReasons.push(`PROMPT_ATTACK filter input_strength = ${d.value || 'NONE'}`);
    } else if (d.kind === 'unresolvable') {
      unresolved ??= d.reason;
      weakReasons.push('PROMPT_ATTACK filter input_strength is expression-driven');
    } else {
      weakReasons.push('PROMPT_ATTACK filter has no input_strength (defaults to NONE)');
    }
  }
  if (unresolved) return { state: 'INCONCLUSIVE', weakReasons, unresolvedReason: unresolved };
  return { state: 'PERMISSIVE', weakReasons };
}

function classifyHarmfulContent(
  filters: Record<string, unknown>[],
  files: ParsedFile[],
  sourceFilePath: string | undefined,
  overlay: PlanOverlay | undefined,
): SurfaceResult {
  const contentFilters = filters.filter((f) => readType(f) !== 'PROMPT_ATTACK');
  if (contentFilters.length === 0) return { state: 'ABSENT', weakReasons: [] };

  const weakReasons: string[] = [];
  let unresolved: UnresolvableReason | undefined;
  for (const f of contentFilters) {
    const din = resolveDecisive(f.input_strength, files, sourceFilePath, overlay);
    const dout = resolveDecisive(f.output_strength, files, sourceFilePath, overlay);
    const inBlocks = din.kind === 'literal' && CONTENT_BLOCKING.has(din.value.toUpperCase());
    const outBlocks = dout.kind === 'literal' && CONTENT_BLOCKING.has(dout.value.toUpperCase());
    if (inBlocks || outBlocks) return { state: 'BLOCKING', weakReasons: [] };
    if (din.kind === 'unresolvable') unresolved ??= din.reason;
    else if (dout.kind === 'unresolvable') unresolved ??= dout.reason;
    weakReasons.push(`content filter ${readType(f) ?? '(untyped)'} input/output strength below MEDIUM`);
  }
  if (unresolved) return { state: 'INCONCLUSIVE', weakReasons, unresolvedReason: unresolved };
  return { state: 'PERMISSIVE', weakReasons };
}

function classifyPii(
  body: Record<string, unknown>,
  files: ParsedFile[],
  sourceFilePath: string | undefined,
  overlay: PlanOverlay | undefined,
): SurfaceResult {
  if (getNestedValue(body, 'sensitive_information_policy_config') === undefined) {
    return { state: 'ABSENT', weakReasons: [] };
  }
  const entries = [
    ...blocks(body, 'sensitive_information_policy_config.pii_entities_config'),
    ...blocks(body, 'sensitive_information_policy_config.regexes_config'),
  ];
  if (entries.length === 0) {
    return { state: 'PERMISSIVE', weakReasons: ['sensitive_information_policy_config declared with no entries'] };
  }

  let unresolved: UnresolvableReason | undefined;
  let anyBlock = false;
  let anyAnonymize = false;
  for (const e of entries) {
    const d = resolveDecisive(e.action, files, sourceFilePath, overlay);
    if (d.kind === 'literal') {
      const action = d.value.toUpperCase();
      if (action === 'BLOCK') anyBlock = true;
      else if (action === 'ANONYMIZE') anyAnonymize = true;
    } else if (d.kind === 'unresolvable') {
      unresolved ??= d.reason;
    }
  }

  if (anyBlock || anyAnonymize) {
    // ANONYMIZE redacts PII in output and so counts as enforcing. The
    // BLOCK-vs-ANONYMIZE nuance survives as an advisory note, not a status change.
    const weakReasons =
      anyAnonymize && !anyBlock
        ? ['PII enforced via ANONYMIZE - consider BLOCK for structurally-sensitive regulated identifiers']
        : [];
    return { state: 'BLOCKING', weakReasons };
  }
  if (unresolved) return { state: 'INCONCLUSIVE', weakReasons: [], unresolvedReason: unresolved };
  return { state: 'PERMISSIVE', weakReasons: ['all PII / regex actions set to NONE'] };
}

function classifyGrounding(
  body: Record<string, unknown>,
  files: ParsedFile[],
  sourceFilePath: string | undefined,
  overlay: PlanOverlay | undefined,
): SurfaceResult {
  if (getNestedValue(body, 'contextual_grounding_policy_config') === undefined) {
    return { state: 'ABSENT', weakReasons: [] };
  }
  const filters = blocks(body, 'contextual_grounding_policy_config.filters_config');
  if (filters.length === 0) {
    return { state: 'PERMISSIVE', weakReasons: ['contextual_grounding_policy_config declared with no filters'] };
  }

  let unresolved: UnresolvableReason | undefined;
  for (const f of filters) {
    const type = readType(f);
    if (type !== 'GROUNDING' && type !== 'RELEVANCE') continue;
    const d = resolveDecisive(f.threshold, files, sourceFilePath, overlay);
    if (d.kind === 'literal') {
      if (Number(d.value) > 0) return { state: 'BLOCKING', weakReasons: [] };
    } else if (d.kind === 'unresolvable') {
      unresolved ??= d.reason;
    }
  }
  if (unresolved) return { state: 'INCONCLUSIVE', weakReasons: [], unresolvedReason: unresolved };
  return { state: 'PERMISSIVE', weakReasons: ['contextual grounding threshold = 0'] };
}

function countDenyTopics(body: Record<string, unknown>): number {
  return blocks(body, 'topic_policy_config.topics_config').filter((t) => {
    if (readType(t) !== 'DENY') return false;
    const name = t.name;
    const def = t.definition;
    return (
      (typeof name === 'string' && name.trim() !== '') ||
      (typeof def === 'string' && def.trim() !== '')
    );
  }).length;
}

// --- helpers ---------------------------------------------------------------

// A for_each / dynamic block makes the surface unverifiable statically. Promote
// a non-BLOCKING static result to INCONCLUSIVE (complex-interpolation) so --plan
// can resolve it; a static BLOCKING filter still wins (the dynamic block can
// only add more enforcement, not remove it).
function withDynamic(result: SurfaceResult, dynamic: boolean): SurfaceResult {
  if (!dynamic || result.state === 'BLOCKING' || result.state === 'INCONCLUSIVE') return result;
  return {
    state: 'INCONCLUSIVE',
    weakReasons: ['content_policy_config uses a dynamic/for_each filters_config block'],
    unresolvedReason: 'complex-interpolation',
  };
}

function hasDynamicBlock(block: unknown): boolean {
  const b = Array.isArray(block) && block.length === 1 ? block[0] : block;
  return typeof b === 'object' && b !== null && 'dynamic' in (b as Record<string, unknown>);
}

// Resolve a guardrail body field that gates a surface verdict. Numbers/booleans
// are literals as-is; strings are resolved through the resolver (so a
// local/var that points at a literal "HIGH" counts as blocking, and a plan
// overlay can resolve a var with no static default).
function resolveDecisive(
  raw: unknown,
  files: ParsedFile[],
  sourceFilePath: string | undefined,
  overlay: PlanOverlay | undefined,
): Decisive {
  if (raw === undefined || raw === null) return { kind: 'absent' };
  if (typeof raw === 'number' || typeof raw === 'boolean') {
    return { kind: 'literal', value: String(raw) };
  }
  if (typeof raw !== 'string') return { kind: 'absent' };
  if (!isUnresolvedScalar(raw)) return { kind: 'literal', value: raw };

  const resolved = resolveExpression(raw, files, 'guardrail-body', sourceFilePath, overlay);
  if (resolved?.kind === 'literal') return { kind: 'literal', value: resolved.value };
  if (resolved?.kind === 'unresolvable') return { kind: 'unresolvable', reason: resolved.reason };
  // 'address' kind (a resource reference) or undefined: treat as unverifiable.
  return { kind: 'unresolvable', reason: 'unknown-format' };
}

// Read a nested block's `type` attribute, upper-cased. Returns undefined when
// the type is absent or expression-driven (so it won't spuriously match a
// known category like PROMPT_ATTACK).
function readType(block: Record<string, unknown>): string | undefined {
  const type = block.type;
  if (typeof type !== 'string') return undefined;
  if (isUnresolvedScalar(type)) return undefined;
  return type.toUpperCase();
}

// Normalise a dotted-path nested-block value into an array of block objects.
// hcl2json emits a single repeated block as an object (auto-unwrapped by
// getNestedValue) and multiple as an array; this collapses both to an array.
function blocks(body: Record<string, unknown>, path: string): Record<string, unknown>[] {
  const value = getNestedValue(body, path);
  if (value === undefined || value === null) return [];
  const arr = Array.isArray(value) ? value : [value];
  return arr.filter((v): v is Record<string, unknown> => typeof v === 'object' && v !== null);
}

function guardrailLabel(name: string, attachingAgents: string[]): string {
  if (attachingAgents.length > 0) {
    return `aws_bedrock_guardrail.${name} (attached to agent(s): ${attachingAgents.join(', ')})`;
  }
  return `aws_bedrock_guardrail.${name}`;
}

// Describe conditional + informational surfaces for PASS / mandatory-gap WARN
// finding text. Never gates status - context only.
function conditionalContext(
  pii: SurfaceResult,
  grounding: SurfaceResult,
  denyTopics: number,
): string {
  const enforcing: string[] = [];
  const notConfigured: string[] = [];

  if (pii.state === 'BLOCKING') {
    enforcing.push(pii.weakReasons.length > 0 ? `PII (${pii.weakReasons[0]})` : 'PII');
  } else if (pii.state === 'ABSENT') {
    notConfigured.push('PII surface not configured - may be handled upstream');
  }

  if (grounding.state === 'BLOCKING') enforcing.push('contextual grounding');
  else if (grounding.state === 'ABSENT') notConfigured.push('grounding not configured - N/A if non-RAG');

  let text = '';
  if (enforcing.length > 0) text += ` Also enforcing: ${enforcing.join(', ')}.`;
  if (notConfigured.length > 0) text += ` Not configured: ${notConfigured.join('; ')}.`;
  if (denyTopics > 0) text += ` ${denyTopics} denied topic(s) declared (informational).`;
  return text;
}

function emptyRemediation(): string {
  return (
    'Populate the guardrail body: add a content_policy_config.filters_config block with ' +
    'type = "PROMPT_ATTACK" and input_strength set to any non-NONE value ("LOW", "MEDIUM", ' +
    'or "HIGH"; "MEDIUM"/"HIGH" recommended), and at least one ' +
    `harmful-content filter (e.g. type = "HATE") set to "MEDIUM"/"HIGH". ${VENDOR_SCOPE_NOTE}`
  );
}

function gapRemediation(): string {
  return (
    'Add a PROMPT_ATTACK filter with input_strength set to any non-NONE value ("LOW", ' +
    '"MEDIUM", or "HIGH"; "MEDIUM"/"HIGH" recommended), and set at least ' +
    'one harmful-content filter category to "MEDIUM"/"HIGH". PII redaction and contextual ' +
    `grounding are suggested where applicable but do not gate this check. ${VENDOR_SCOPE_NOTE}`
  );
}
