import { describe, it, expect } from 'vitest';
import { formatJson, formatSarif } from '../../src/formatter';
import { Finding } from '../../src/types';
import { allRules } from '../../src/rules';

describe('formatJson', () => {
  it('should output valid JSON with summary and findings', () => {
    const findings: Finding[] = [
      {
        ruleId: 'S-12.1.1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'Bedrock logging configured',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1)',
      },
      {
        ruleId: 'S-12.x.4',
        status: 'FAIL',
        filePath: 'test.tf',
        description: 'No CloudTrail',
        remediation: 'Add CloudTrail',
        regulatoryReference: 'EU AI Act Article 12',
      },
    ];

    const output = formatJson(findings);
    const parsed = JSON.parse(output);

    expect(parsed.summary).toEqual({
      total: 2,
      pass: 1,
      fail: 1,
      warn: 0,
      skip: 0,
      inconclusive: 0,
    });
    expect(parsed.findings).toHaveLength(2);
  });

  it('should emit structured frameworks array on each finding', () => {
    const findings: Finding[] = [
      {
        ruleId: 'S-12.1.1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'Bedrock logging configured',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1) - Automatic logging of events',
        nistReference:
          'NIST AI RMF 1.0: GOVERN 1.4 (transparent risk-management policies); MEASURE 2.7 (security and resilience)',
        isoReference:
          'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (AI system operation and monitoring)',
      },
    ];

    const parsed = JSON.parse(formatJson(findings));
    expect(parsed.findings[0].frameworks).toEqual([
      {
        framework: 'EU AI Act',
        items: [{ id: 'Article 12(1)', desc: 'Automatic logging of events' }],
      },
      {
        framework: 'NIST AI RMF',
        items: [
          { id: 'GOVERN 1.4', desc: 'transparent risk-management policies' },
          { id: 'MEASURE 2.7', desc: 'security and resilience' },
        ],
      },
      {
        framework: 'ISO/IEC 42001',
        items: [
          { id: 'A.6.2.8', desc: 'AI system event logs' },
          { id: 'A.6.2.6', desc: 'AI system operation and monitoring' },
        ],
      },
    ]);
    // Raw strings preserved for backwards compatibility.
    expect(parsed.findings[0].regulatoryReference).toContain('Article 12(1)');
    expect(parsed.findings[0].nistReference).toContain('GOVERN 1.4');
    expect(parsed.findings[0].isoReference).toContain('A.6.2.8');
  });

  it('splits a multi-article EU citation into one numbers-only pill per article (paren form)', () => {
    // Regression: the EU parser used to split on the first " - ", but a dash can
    // sit *inside* a parenthesised description (e.g. S-9.x.3). That truncated the
    // first pill to "Art. 9(2)(d) (appropriate and targeted..." and silently
    // dropped Art. 9(5)(b), 15(4), 15(5) entirely.
    const findings: Finding[] = [
      {
        ruleId: 'S-9.x.3',
        status: 'WARN',
        filePath: 'test.tf',
        description: 'guardrail body',
        remediation: '',
        regulatoryReference:
          'EU AI Act Art. 9(2)(d) (appropriate and targeted risk management measures - ' +
          'applies where the system is high-risk under Art. 6/Annex III); ' +
          'Art. 9(5)(b) (adequate mitigation and control measures for risks that cannot ' +
          'be eliminated by design); ' +
          'Art. 15(4) (resilience to errors and inconsistencies - anchors the contextual ' +
          'grounding surface, i.e. hallucination resistance); ' +
          'Art. 15(5) ¶3 (adversarial examples / model evasion and confidentiality attacks ' +
          '- PROMPT_ATTACK filter and PII BLOCK respectively)',
      },
    ];

    const parsed = JSON.parse(formatJson(findings));
    const eu = parsed.findings[0].frameworks.find(
      (g: { framework: string }) => g.framework === 'EU AI Act',
    );

    // Pills are numbers only - no prose, no stray open paren.
    expect(eu.items.map((i: { id: string }) => i.id)).toEqual([
      'Art. 9(2)(d)',
      'Art. 9(5)(b)',
      'Art. 15(4)',
      'Art. 15(5) ¶3',
    ]);
    // Prose is preserved for the hover tooltip, not lost.
    expect(eu.items[0].desc).toContain('appropriate and targeted risk management measures');
    expect(eu.items[3].desc).toContain('PROMPT_ATTACK');
  });

  it('keeps every article when an EU citation lists several in dash form', () => {
    // s3-versioning / s3-encryption cite two articles; the second used to be dropped.
    const findings: Finding[] = [
      {
        ruleId: 'S-12.x.1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'versioning',
        remediation: '',
        regulatoryReference:
          'EU AI Act Article 19(1) - Logs must be kept intact for at least six months ' +
          '(versioning/Object Lock preserves them against silent overwrite or deletion); ' +
          'Article 15(5) - resilience against unauthorised alteration of system outputs',
      },
    ];

    const parsed = JSON.parse(formatJson(findings));
    const eu = parsed.findings[0].frameworks.find(
      (g: { framework: string }) => g.framework === 'EU AI Act',
    );

    expect(eu.items).toEqual([
      {
        id: 'Article 19(1)',
        desc: 'Logs must be kept intact for at least six months (versioning/Object Lock preserves them against silent overwrite or deletion)',
      },
      { id: 'Article 15(5)', desc: 'resilience against unauthorised alteration of system outputs' },
    ]);
  });

  it('should omit frameworks entries with no parsed items', () => {
    const findings: Finding[] = [
      {
        ruleId: 'X-1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'No refs',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1) - Logging',
      },
    ];

    const parsed = JSON.parse(formatJson(findings));
    expect(parsed.findings[0].frameworks).toHaveLength(1);
    expect(parsed.findings[0].frameworks[0].framework).toBe('EU AI Act');
  });
});

describe('formatSarif', () => {
  const sampleFindings: Finding[] = [
    {
      ruleId: 'S-12.1.1',
      status: 'FAIL',
      filePath: 'modules/bedrock/main.tf',
      line: 42,
      description: 'Bedrock invocation logging is not configured',
      remediation: 'Declare aws_bedrock_model_invocation_logging_configuration',
      regulatoryReference: 'EU AI Act Article 12(1) - Automatic logging of events',
      nistReference:
        'NIST AI RMF 1.0: GOVERN 1.4 (transparent risk-management policies); MEASURE 2.7 (security and resilience)',
      isoReference:
        'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs)',
    },
    {
      ruleId: 'S-12.1.2a',
      status: 'WARN',
      filePath: 'modules/bedrock/main.tf',
      line: 88,
      description: 'CloudWatch retention below 180 days',
      remediation: 'Set retention_in_days to >= 365',
      regulatoryReference: 'EU AI Act Article 12(2)',
    },
    {
      ruleId: 'S-12.x.4',
      status: 'PASS',
      filePath: 'cloudtrail.tf',
      description: 'CloudTrail enabled',
      remediation: '',
      regulatoryReference: 'EU AI Act Article 12',
    },
    {
      ruleId: 'S-12.x.1',
      status: 'INCONCLUSIVE',
      filePath: 'modules/logs/main.tf',
      description: 'Bucket name resolves through var without default',
      remediation: 'Add a default to var.log_bucket_name',
      regulatoryReference: 'EU AI Act Article 12',
      unresolvedReason: 'var-no-default',
    },
    {
      ruleId: 'S-9.x.1',
      status: 'SKIP',
      filePath: '',
      description: 'No Bedrock agents in scope',
      remediation: '',
      regulatoryReference: 'EU AI Act Article 9',
    },
  ];

  it('emits a SARIF 2.1.0 document with one run and the infrarails tool driver', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('infrarails');
    // version is single-sourced from package.json (injected via define) — assert
    // it is a real non-empty string and that semanticVersion mirrors it.
    const driver = sarif.runs[0].tool.driver;
    expect(typeof driver.version).toBe('string');
    expect(driver.version.length).toBeGreaterThan(0);
    expect(driver.semanticVersion).toBe(driver.version);
    expect(driver.informationUri).toMatch(/^https:\/\//);
  });

  it('includes the full rule catalogue, not just rules with findings', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: { id: string }) => r.id);
    // Every registered rule should be advertised - giving consumers a stable
    // catalogue of what infrarails can find.
    for (const r of allRules) {
      expect(ruleIds).toContain(r.id);
    }
  });

  it('tags every rule with a GitHub Code Scanning security-severity matching its severity', () => {
    // GitHub Code Scanning only ranks/sorts alerts when each rule carries a
    // numeric security-severity. FAIL = '7.0' (high), WARN = '4.0' (medium).
    // Cross-reference allRules by id so this stays valid as rules change.
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const severityById = new Map(allRules.map((r) => [r.id, r.severity]));
    const rules: { id: string; properties: { 'security-severity': string } }[] =
      sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBeGreaterThan(0);
    for (const rule of rules) {
      const severity = severityById.get(rule.id);
      const expected = severity === 'FAIL' ? '7.0' : '4.0';
      expect(rule.properties['security-severity']).toBe(expected);
    }
  });

  it('maps statuses to SARIF level + kind correctly', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const byRule = new Map<string, { level: string; kind: string }>(
      sarif.runs[0].results.map((r: { ruleId: string; level: string; kind: string }) => [
        r.ruleId,
        { level: r.level, kind: r.kind },
      ]),
    );

    expect(byRule.get('S-12.1.1')).toEqual({ level: 'error', kind: 'fail' });
    expect(byRule.get('S-12.1.2a')).toEqual({ level: 'warning', kind: 'fail' });
    expect(byRule.get('S-12.x.4')).toEqual({ level: 'none', kind: 'pass' });
    // SARIF 3.27.9: a non-'fail' kind requires level='none'. INCONCLUSIVE stays
    // visible as a warning, so kind must be 'fail' (verdict lives in properties.status).
    expect(byRule.get('S-12.x.1')).toEqual({ level: 'warning', kind: 'fail' });
    expect(byRule.get('S-9.x.1')).toEqual({ level: 'none', kind: 'notApplicable' });
  });

  it('honours the SARIF 3.27.9 invariant: kind !== "fail" implies level === "none"', () => {
    // Regression net across every status: GitHub treats warning+non-fail-kind
    // unpredictably, so any result whose kind is not 'fail' must carry level 'none'.
    const sarif = JSON.parse(formatSarif(sampleFindings));
    for (const r of sarif.runs[0].results as { kind: string; level: string }[]) {
      if (r.kind !== 'fail') {
        expect(r.level).toBe('none');
      }
    }
  });

  it('sets runs[0].automationDetails.id from the category option (GitHub Code Scanning category)', () => {
    // Default: the tool name. Without automationDetails.id, two upload-sarif
    // uploads on one commit silently overwrite each other.
    const defaultSarif = JSON.parse(formatSarif(sampleFindings));
    expect(defaultSarif.runs[0].automationDetails.id).toBe('infrarails');

    const categorised = JSON.parse(formatSarif(sampleFindings, { category: 'terraform' }));
    expect(categorised.runs[0].automationDetails.id).toBe('terraform');
  });

  it('emits a result for every finding (including PASS / SKIP for the audit trail)', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    expect(sarif.runs[0].results).toHaveLength(sampleFindings.length);
  });

  it('attaches physical locations with line numbers when available', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.locations).toHaveLength(1);
    expect(fail.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'modules/bedrock/main.tf',
    );
    expect(fail.locations[0].physicalLocation.region.startLine).toBe(42);
  });

  it('omits the region when no line number is supplied', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const pass = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.x.4');
    expect(pass.locations[0].physicalLocation.artifactLocation.uri).toBe('cloudtrail.tf');
    expect(pass.locations[0].physicalLocation.region).toBeUndefined();
  });

  it('emits a synthetic %SRCROOT% location when filePath is empty (tree-wide findings)', () => {
    // GitHub Code Scanning rejects results with zero locations
    // ("locationFromSarifResult: expected at least one location"). The
    // emitter must synthesize a scan-root anchor instead of dropping the
    // finding's location entirely.
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const skip = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-9.x.1');
    expect(skip.locations).toHaveLength(1);
    expect(skip.locations[0].physicalLocation.artifactLocation.uri).toBe('.');
    expect(skip.locations[0].physicalLocation.artifactLocation.uriBaseId).toBe('%SRCROOT%');
  });

  it('rewrites plan:<address> URIs to a synthetic %SRCROOT% location and preserves the plan address in properties', () => {
    // `plan:<address>` is an unknown URI scheme to GitHub - it silently
    // strips the location, leaving zero locations on the result, and then
    // drops the result. Rewrite to a resolvable URI while preserving the
    // citation in properties.planAddress.
    const planFindings: Finding[] = [
      {
        ruleId: 'S-12.x.del',
        status: 'FAIL',
        filePath: 'plan:module.bedrock_governance.aws_bedrock_model_invocation_logging_configuration.this',
        description: 'Bedrock invocation logging scheduled for destruction',
        remediation: 'Restore the resource before applying.',
        regulatoryReference: 'EU AI Act Article 12(1)',
      },
    ];
    const sarif = JSON.parse(formatSarif(planFindings));
    const result = sarif.runs[0].results[0];
    expect(result.locations).toHaveLength(1);
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('.');
    expect(result.locations[0].physicalLocation.artifactLocation.uriBaseId).toBe('%SRCROOT%');
    expect(result.locations[0].properties.planAddress).toBe(
      'module.bedrock_governance.aws_bedrock_model_invocation_logging_configuration.this',
    );
  });

  it('declares originalUriBaseIds["%SRCROOT%"] on each run so GitHub can anchor synthetic locations', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const baseIds = sarif.runs[0].originalUriBaseIds;
    expect(baseIds).toBeDefined();
    expect(baseIds['%SRCROOT%']).toBeDefined();
    expect(baseIds['%SRCROOT%'].uri).toMatch(/^file:/);
  });

  it('guarantees every result carries at least one location (GitHub upload invariant)', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    for (const r of sarif.runs[0].results as { ruleId: string; locations: unknown[] }[]) {
      expect(r.locations.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('emits only resolvable URIs (no plan:// or other unknown schemes)', () => {
    // Mix the sample (which has an empty-filePath SKIP) with a synthetic
    // plan-prefixed finding to exercise both rewrites in one pass.
    const findings: Finding[] = [
      ...sampleFindings,
      {
        ruleId: 'S-12.x.del',
        status: 'WARN',
        filePath: 'plan:aws_s3_bucket.logs',
        description: 'Replacement scheduled',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1)',
      },
    ];
    const sarif = JSON.parse(formatSarif(findings));
    for (const r of sarif.runs[0].results as {
      locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
    }[]) {
      for (const loc of r.locations) {
        const uri = loc.physicalLocation.artifactLocation.uri;
        // Either a relative URI (no scheme), or a recognised scheme. plan:
        // and other custom schemes must never leak through to GitHub.
        const schemeMatch = uri.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):/);
        if (schemeMatch) {
          expect(schemeMatch[1].toLowerCase()).toBe('file');
        }
      }
    }
  });

  it('folds description + remediation into message.text', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.message.text).toContain('Bedrock invocation logging is not configured');
    expect(fail.message.text).toContain('Remediation:');
    expect(fail.message.text).toContain('aws_bedrock_model_invocation_logging_configuration');
  });

  it('omits the remediation suffix when remediation is empty', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const pass = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.x.4');
    expect(pass.message.text).toBe('CloudTrail enabled');
    expect(pass.message.text).not.toContain('Remediation');
  });

  it('exposes raw references, parsed frameworks, and unresolvedReason in properties', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.properties.status).toBe('FAIL');
    expect(fail.properties.regulatoryReference).toMatch(/Article 12\(1\)/);
    expect(fail.properties.nistReference).toMatch(/GOVERN 1\.4/);
    expect(fail.properties.isoReference).toMatch(/A\.6\.2\.8/);
    expect(fail.properties.frameworks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ framework: 'EU AI Act' }),
        expect.objectContaining({ framework: 'NIST AI RMF' }),
        expect.objectContaining({ framework: 'ISO/IEC 42001' }),
      ]),
    );
    expect(fail.properties.remediation).toBeDefined();

    const inconclusive = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === 'S-12.x.1',
    );
    expect(inconclusive.properties.unresolvedReason).toBe('var-no-default');
  });

  it('includes partialFingerprints so GitHub Code Scanning can dedupe across runs', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    // The fingerprint must be line-independent: it keys on filePath only, with
    // no `:42` line suffix. Embedding the line would change the fingerprint
    // whenever code shifts the line, defeating GitHub's cross-run dedupe.
    expect(fail.partialFingerprints).toMatchObject({
      'ruleId/v1': 'S-12.1.1',
      'location/v1': 'modules/bedrock/main.tf',
    });
  });

  it('sets ruleIndex to point at the rule in the driver.rules catalogue', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const rules: { id: string }[] = sarif.runs[0].tool.driver.rules;
    for (const result of sarif.runs[0].results as { ruleId: string; ruleIndex: number }[]) {
      expect(rules[result.ruleIndex].id).toBe(result.ruleId);
    }
  });

  it('produces an empty results array when there are no findings', () => {
    const sarif = JSON.parse(formatSarif([]));
    expect(sarif.runs[0].results).toEqual([]);
    // Catalogue is still emitted.
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
  });

  it('derives honest per-rule tags (compliance/security/eu-ai-act always; nist/iso only when mapped)', () => {
    // Tag-based filtering in consumers must be accurate: a rule with no NIST or
    // ISO mapping must not advertise those tags. Cross-reference allRules by id
    // so this stays valid as rules and their mappings change.
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const ruleById = new Map(allRules.map((r) => [r.id, r]));
    const rules: { id: string; properties: { tags: string[] } }[] =
      sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBeGreaterThan(0);
    for (const rule of rules) {
      const source = ruleById.get(rule.id)!;
      const tags = rule.properties.tags;
      // Always present (regulatoryReference is required; 'security' activates
      // the security-severity ranking in GitHub's Security tab).
      expect(tags).toContain('compliance');
      expect(tags).toContain('security');
      expect(tags).toContain('eu-ai-act');
      // Present IFF the rule actually maps to that framework.
      expect(tags.includes('nist-ai-rmf')).toBe(Boolean(source.nistReference));
      expect(tags.includes('iso-42001')).toBe(Boolean(source.isoReference));
    }
  });

  it('makes fullDescription a strict, citation-bearing superset of shortDescription', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const ruleById = new Map(allRules.map((r) => [r.id, r]));
    const rules: {
      id: string;
      shortDescription: { text: string };
      fullDescription: { text: string };
    }[] = sarif.runs[0].tool.driver.rules;
    // Pick a representative rule that carries the required EU citation.
    const rule = rules.find((r) => Boolean(ruleById.get(r.id)?.regulatoryReference));
    expect(rule).toBeDefined();
    const source = ruleById.get(rule!.id)!;
    expect(rule!.fullDescription.text).not.toBe(rule!.shortDescription.text);
    expect(rule!.fullDescription.text).toContain(rule!.shortDescription.text);
    expect(rule!.fullDescription.text).toContain(source.regulatoryReference);
  });

  it('points each rule helpUri at an https URL', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const rules: { helpUri: string }[] = sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBeGreaterThan(0);
    for (const rule of rules) {
      expect(rule.helpUri).toMatch(/^https:\/\//);
    }
  });
});
