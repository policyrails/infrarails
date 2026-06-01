import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue } from '../utils/resource-helpers';
import { isUnresolvedScalar } from '../utils/literal';
import { buildGuardrailGraph, GuardrailLink } from '../utils/guardrail-graph';

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
  'passed in application code and is not verifiable from Terraform - verify ' +
  'SDK call sites separately. See also rule S-9.x.2 for guardrail-presence ' +
  'detection across the scanned Terraform.';

export const agentGuardrailRule: ScanRule = {
  id: 'S-9.x.1',
  description:
    'Bedrock Agents must have a versioned guardrail attached (Agent-attached guardrails only - raw InvokeModel/Converse SDK calls are out of scope for static IaC scanning)',
  severity: 'FAIL',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    const agents = findResources(files, 'aws_bedrockagent_agent');

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

    return agents.map((agent) => {
      const line = findResourceLine(agent.rawHcl, 'aws_bedrockagent_agent', agent.name);
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

      const id = getNestedValue(guardrail, 'guardrail_identifier');
      const version = getNestedValue(guardrail, 'guardrail_version');

      const idMissing =
        id === undefined || id === null || (typeof id === 'string' && id.trim() === '');

      if (idMissing) {
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

      const link: GuardrailLink = graph.agentToGuardrail.get(agent.name) ?? { kind: 'unresolved' };

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
            `Terraform. It may live in a separate platform/security stack.`,
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
      const idUnresolved = link.kind === 'declared' ? false : isUnresolvedScalar(id);
      const versionUnresolved = version !== undefined && isUnresolvedScalar(version);
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

      if (!version || version === 'DRAFT') {
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
      // back to a declared aws_bedrock_guardrail without --plan.
      const opaqueNote =
        link.kind === 'literal'
          ? ' (identifier is a literal ID/ARN - not mappable to a declared guardrail without --plan)'
          : '';
      return {
        ruleId: this.id,
        status: 'PASS' as const,
        filePath: agent.filePath,
        line,
        description: `Bedrock Agent "${agent.name}" has a versioned guardrail attached (version ${version})${opaqueNote}.`,
        remediation: '',
        regulatoryReference: REGULATORY_REFERENCE,
        nistReference: NIST_REFERENCE,
        isoReference: ISO_REFERENCE,
      };
    });
  },
};
