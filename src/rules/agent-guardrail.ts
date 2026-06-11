import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, cfnConditionOf, inconclusiveConditional } from '../utils/resource-helpers';
import { isUnresolvedScalar } from '../utils/literal';
import { buildGuardrailGraph, GuardrailLink, isDeclaredVersionReference } from '../utils/guardrail-graph';

const REGULATORY_REFERENCE = 'EU AI Act Article 9 - Risk management system for high-risk AI systems';
const NIST_REFERENCE =
  'NIST AI RMF 1.0: MEASURE 2.6 (AI system safety); MAP 5.1 (likelihood and magnitude of impacts); GOVERN 1.4 (transparent risk-management policies)';
const ISO_REFERENCE =
  'ISO/IEC 42001:2023 Annex A: A.6.1.2 (objectives for AI system); A.6.2.4 (verification and validation); A.6.2.5 (deployment)';

const RATIONALE =
  'Bedrock Agents reason in chains, invoke action-group Lambdas, and retrieve from knowledge bases - ' +
  'any of which can produce harmful output (prompt injection, data exfiltration, hallucinated tool calls, ' +
  'denied-topic responses). Article 9 requires an operative risk-management system for high-risk AI; ' +
  'Bedrock Guardrails are the AWS-native enforcement point for content filters, denied topics, PII ' +
  'redaction, and grounding checks. An agent without a guardrail in production has no Article 9 control surface.';

// Static-scan scope note used in every non-PASS finding for this rule.
// Bedrock Guardrails attach to two surfaces: (1) Bedrock Agents via the
// guardrail_configuration block in HCL - the only place a static scanner can
// verify attachment; (2) raw InvokeModel / Converse SDK calls via the
// guardrailIdentifier parameter - this is application code, not Terraform, so
// the scanner cannot see it. This rule only covers (1). Coverage of (2) lives
// at the application layer (code review, SDK linting, runtime tracing) and at
// the org layer (sibling rule S-9.x.2 detects "Bedrock is used but no
// aws_bedrock_guardrail is declared anywhere in scanned files" as a weaker
// presence signal).
const SCOPE_NOTE =
  'Scope: this rule only verifies Agent-attached guardrails. For raw ' +
  'InvokeModel / Converse SDK calls, the guardrailIdentifier parameter is ' +
  'passed in application code and is not verifiable from IaC - verify ' +
  'SDK call sites separately. See also rule S-9.x.2 for guardrail-presence ' +
  'detection across the scanned IaC.';

export const agentGuardrailRule: ScanRule = {
  id: 'S-9.x.1',
  description:
    'Bedrock Agents must have a versioned guardrail attached (Agent-attached guardrails only - raw InvokeModel/Converse SDK calls are out of scope for static IaC scanning)',
  severity: 'FAIL',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    // Discover agents with the overlay so agents buried in remote / not-yet-
    // applied modules (visible only via the plan) are evaluated, consistent
    // with the guardrail graph below which also uses it.
    const agents = findResources(files, 'aws_bedrockagent_agent', context.planOverlay);

    if (agents.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock Agents detected. Guardrail attachment check skipped.',
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    // Decision A: the agent<->guardrail reference graph lets a guardrail
    // attached *by reference* (the correct Terraform idiom) resolve to a
    // declared resource instead of being penalised as INCONCLUSIVE by the
    // ${...} wrapper. Built with the overlay so references resolve against
    // guardrails visible only via the plan (remote modules).
    const graph = buildGuardrailGraph(files, context.planOverlay);

    // Guardrail-version resources declared in scope. An agent whose
    // guardrail_version is wired to one of these is pinned to a published,
    // numbered (immutable) version even when the value is known-after-apply
    // (CFN Fn::GetAtt, or a same-template HCL reference). Identity comes from
    // the reference, not the computed value - the HCL-anchored principle.
    const declaredVersionResources = new Set(
      findResources(files, 'aws_bedrock_guardrail_version', context.planOverlay).map((v) => v.name),
    );

    return agents.map((agent) => {
      const line = findResourceLine(agent.rawHcl, 'aws_bedrockagent_agent', agent.name);

      // Condition-guarded CFN agent: whether it (and its guardrail wiring)
      // exists at deploy time is parameter-dependent.
      const condition = cfnConditionOf(agent.body);
      if (condition) {
        return inconclusiveConditional(this, {
          label: `Bedrock Agent "${agent.name}"`,
          condition,
          filePath: agent.filePath,
          line,
        });
      }

      const guardrail = getNestedValue(agent.body, 'guardrail_configuration');

      if (!guardrail) {
        return {
          ruleId: this.id,
          status: 'FAIL' as const,
          filePath: agent.filePath,
          line,
          description: `Bedrock Agent "${agent.name}" has no guardrail_configuration block - the agent will run with no content filters, denied-topic enforcement, PII redaction, or grounding checks.`,
          remediation:
            'Add a guardrail_configuration block to aws_bedrockagent_agent referencing an ' +
            'aws_bedrock_guardrail (with guardrail_identifier set to the guardrail ID and ' +
            'guardrail_version pinned to a numbered version, not "DRAFT"). ' +
            `Why: ${RATIONALE} ${SCOPE_NOTE}`,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        };
      }

      const link: GuardrailLink = graph.agentToGuardrail.get(agent.name) ?? { kind: 'unresolved' };

      // A reference chain resolved across module boundaries proves attachment
      // even when the wired guardrail_identifier is known-after-apply (and so
      // absent from a plan-sourced agent body). In that case the empty/unset
      // value below is expected, not a gap.
      const resolvedByReference = link.kind === 'declared' || link.kind === 'declared-via-module';

      const id = getNestedValue(guardrail, 'guardrail_identifier');
      const version = getNestedValue(guardrail, 'guardrail_version');

      const idMissing =
        id === undefined || id === null || (typeof id === 'string' && id.trim() === '');

      if (idMissing && !resolvedByReference) {
        return {
          ruleId: this.id,
          status: 'FAIL' as const,
          filePath: agent.filePath,
          line,
          description: `Bedrock Agent "${agent.name}" declares guardrail_configuration but guardrail_identifier is empty or unset - no guardrail is actually attached.`,
          remediation:
            'Set guardrail_identifier to the ID (or ARN) of an aws_bedrock_guardrail resource. ' +
            `Why: ${RATIONALE} ${SCOPE_NOTE}`,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        };
      }

      // Decision A: a guardrail attached by reference to a definition NOT in
      // the scanned Terraform is a referential gap. WARN (not FAIL) - the
      // guardrail genuinely may live in a separate platform/security stack,
      // same reasoning as S-9.x.2.
      if (link.kind === 'reference-external') {
        return {
          ruleId: this.id,
          status: 'WARN' as const,
          filePath: agent.filePath,
          line,
          description:
            `Bedrock Agent "${agent.name}" attaches a guardrail by reference ` +
            `(aws_bedrock_guardrail.${link.guardrail}) whose definition is not in the scanned ` +
            `IaC. It may live in a separate platform/security stack.`,
          remediation:
            'Scan the stack that declares aws_bedrock_guardrail.' +
            `${link.guardrail}, or document the cross-stack arrangement. ` +
            `Why: ${RATIONALE} ${SCOPE_NOTE}`,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        };
      }

      // If guardrail_identifier or guardrail_version is expression-driven
      // (var/local/data/module reference), we cannot prove the attached
      // guardrail is a real, versioned resource. Report INCONCLUSIVE rather
      // than passing optimistically - this is the conservative-by-default
      // behaviour the README promises. A reference to a guardrail declared
      // in scope is referentially resolved, so only an unresolved *version*
      // keeps it INCONCLUSIVE (Decision A: the correct idiom no longer trips
      // the ${...}-wrapper INCONCLUSIVE).
      const idUnresolved = resolvedByReference ? false : isUnresolvedScalar(id);
      // A version pinned through the reference chain (an aws_bedrock_guardrail_version
      // resource) is resolved even when the literal value is known-after-apply.
      // Two equivalent forms count: the cross-module config walk (declared-via-
      // module), and a direct reference to an in-scope guardrail_version resource
      // (a CFN Fn::GetAtt [GRVersion, Version], or a same-template HCL ref).
      const versionPinnedByReference =
        (link.kind === 'declared-via-module' && link.versionPin === 'versioned') ||
        isDeclaredVersionReference(version, declaredVersionResources);
      const versionUnresolved =
        !versionPinnedByReference && version !== undefined && isUnresolvedScalar(version);
      if (idUnresolved || versionUnresolved) {
        const fields: string[] = [];
        if (idUnresolved) fields.push(`guardrail_identifier=${id}`);
        if (versionUnresolved) fields.push(`guardrail_version=${version}`);
        return {
          ruleId: this.id,
          status: 'INCONCLUSIVE' as const,
          filePath: agent.filePath,
          line,
          description:
            `Bedrock Agent "${agent.name}" attaches a guardrail via a non-literal expression ` +
            `(${fields.join(', ')}). The scanner cannot statically verify that the attached ` +
            `guardrail exists or is pinned to a numbered version.`,
          remediation:
            'Inline a literal guardrail_identifier and a numbered guardrail_version, or rerun ' +
            'the scan with resolved values (e.g. via terraform plan output) so attachment can ' +
            `be verified. Why: ${RATIONALE} ${SCOPE_NOTE}`,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        };
      }

      if (!versionPinnedByReference && (!version || version === 'DRAFT')) {
        return {
          ruleId: this.id,
          status: 'WARN' as const,
          filePath: agent.filePath,
          line,
          description: `Bedrock Agent "${agent.name}" references a guardrail with version "${version || 'unset'}" - DRAFT/unset versions are mutable and not auditable as a fixed control.`,
          remediation:
            'Pin guardrail_version to a numbered version (e.g. "1", "2") published from an ' +
            'aws_bedrock_guardrail_version resource. DRAFT versions can be edited in place, so ' +
            'a passing audit today can be a failing one tomorrow with no Terraform diff. ' +
            `Why: ${RATIONALE} ${SCOPE_NOTE}`,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        };
      }

      // A literal ID/ARN passes on a numbered version, but it is opaque: a
      // guardrail's guardrail_id is known-after-apply, so it cannot be mapped
      // back to a declared aws_bedrock_guardrail without --plan. A
      // declared-via-module link, by contrast, was traced to a specific
      // in-scope guardrail through the plan configuration graph.
      const attachNote =
        link.kind === 'declared-via-module'
          ? ` (guardrail resolved across module boundary to aws_bedrock_guardrail.${link.guardrail} via plan configuration)`
          : link.kind === 'literal'
            ? ' (identifier is a literal ID/ARN - not mappable to a declared guardrail without --plan)'
            : '';
      // For a reference-pinned version the literal value is known-after-apply
      // (or an unresolved var expression); describe the pin by its source
      // instead of printing "undefined" or a raw "${var.x}".
      const versionText = versionPinnedByReference
        ? 'version pinned via aws_bedrock_guardrail_version'
        : `version ${version}`;
      return {
        ruleId: this.id,
        status: 'PASS' as const,
        filePath: agent.filePath,
        line,
        description: `Bedrock Agent "${agent.name}" has a versioned guardrail attached (${versionText})${attachNote}.`,
        remediation: '',
        regulatoryReference: REGULATORY_REFERENCE,
        nistReference: NIST_REFERENCE,
        isoReference: ISO_REFERENCE,
      };
    });
  },
};
