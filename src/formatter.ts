import chalk from 'chalk';
import { Finding, FindingStatus } from './types';
import { allRules } from './rules';
import { sourceOfPath } from './cfn/source';

interface ScanSummary {
  total: number;
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  inconclusive: number;
}

const STATUS_ORDER: FindingStatus[] = ['FAIL', 'WARN', 'INCONCLUSIVE', 'PASS', 'SKIP'];

function summarize(findings: Finding[]): ScanSummary {
  return {
    total: findings.length,
    pass: findings.filter((f) => f.status === 'PASS').length,
    fail: findings.filter((f) => f.status === 'FAIL').length,
    warn: findings.filter((f) => f.status === 'WARN').length,
    skip: findings.filter((f) => f.status === 'SKIP').length,
    inconclusive: findings.filter((f) => f.status === 'INCONCLUSIVE').length,
  };
}

function groupByStatus(findings: Finding[]): Map<FindingStatus, Finding[]> {
  const groups = new Map<FindingStatus, Finding[]>();
  for (const status of STATUS_ORDER) groups.set(status, []);
  for (const f of findings) groups.get(f.status)!.push(f);
  return groups;
}

interface ParsedRef {
  framework: string; // "EU AI Act" / "NIST AI RMF" / "ISO/IEC 42001"
  items: { id: string; desc?: string }[];
}

// Parse the verbose reference strings from rules into structured (id, desc) pairs.
// Single source of truth so terminal and HTML can render compactly without
// asking each rule to duplicate data.
function parseRef(s: string | undefined, kind: 'eu' | 'nist' | 'iso'): ParsedRef | null {
  if (!s) return null;
  if (kind === 'eu') {
    // EU strings cite one or more articles, in either a dash form or a
    // paren form:
    //   "EU AI Act Article 19(1) - <prose>; Article 15(5) - <prose>"
    //   "EU AI Act Art. 9(2)(d) (<prose>); Art. 15(5) ¶3 (<prose>)"
    // The article number itself carries parenthesised sub-paragraphs
    // ("9(2)(d)", "15(5) ¶3"), so anchor the id on the leading article token
    // and treat whatever follows - dash-led or paren-wrapped - as the tooltip
    // prose. A dash *inside* that prose must not be mistaken for the id/desc
    // separator: that mistake truncated multi-article citations to a mangled
    // first fragment ("Art. 9(2)(d) (appropriate and targeted...") and silently
    // dropped the remaining articles.
    const body = s.replace(/^EU AI Act\s+/, '');
    const items = body
      .split(';')
      .map((p) => p.trim())
      .filter(Boolean)
      .map((cite) => {
        const m = cite.match(/^(Art\.|Article)\s+(\d+(?:\([0-9a-z]+\))*(?:\s*¶\s*\d+)?)\s*(.*)$/s);
        if (!m) return { id: cite, desc: undefined };
        const id = `${m[1]} ${m[2]}`.replace(/\s+/g, ' ').trim();
        let desc = m[3].trim();
        if (desc.startsWith('- ')) desc = desc.slice(2).trim();
        else if (desc.startsWith('(') && desc.endsWith(')')) desc = desc.slice(1, -1).trim();
        return { id, desc: desc || undefined };
      });
    return { framework: 'EU AI Act', items };
  }
  // NIST/ISO share format: "<Framework>: <ID> (<desc>); <ID> (<desc>)"
  // Use the last ": " (colon-space) so we skip embedded version numbers like
  // "ISO/IEC 42001:2023 Annex A:" - the items start after the trailing ": ".
  const split = s.lastIndexOf(': ');
  if (split < 0) return { framework: kind === 'nist' ? 'NIST AI RMF' : 'ISO/IEC 42001', items: [] };
  const framework = kind === 'nist' ? 'NIST AI RMF' : 'ISO/IEC 42001';
  const rest = s.slice(split + 2).trim();
  const parts = rest.split(';').map((p) => p.trim()).filter(Boolean);
  const items = parts.map((p) => {
    const m = p.match(/^(.+?)\s*\(([^)]+)\)\s*$/);
    return m ? { id: m[1].trim(), desc: m[2].trim() } : { id: p, desc: undefined };
  });
  return { framework, items };
}

function findingRefs(f: Finding): ParsedRef[] {
  return [
    parseRef(f.regulatoryReference, 'eu'),
    parseRef(f.nistReference, 'nist'),
    parseRef(f.isoReference, 'iso'),
  ].filter((r): r is ParsedRef => r !== null && r.items.length > 0);
}

// ─────────────────────────────────────────────────────────────────────
// Terminal
// ─────────────────────────────────────────────────────────────────────

function statusIcon(status: FindingStatus): string {
  switch (status) {
    case 'PASS': return chalk.green('✓');
    case 'FAIL': return chalk.red('✗');
    case 'WARN': return chalk.yellow('⚠');
    case 'SKIP': return chalk.gray('-');
    case 'INCONCLUSIVE': return chalk.magenta('?');
  }
}

function statusColor(status: FindingStatus): (text: string) => string {
  switch (status) {
    case 'PASS': return chalk.green;
    case 'FAIL': return chalk.red;
    case 'WARN': return chalk.yellow;
    case 'SKIP': return chalk.gray;
    case 'INCONCLUSIVE': return chalk.magenta;
  }
}

function compactRefLine(refs: ParsedRef[]): string {
  // "EU 12(1) · NIST GOVERN 1.4, MEASURE 2.7 · ISO A.6.2.8, A.6.2.6"
  const shortName: Record<string, string> = {
    'EU AI Act': 'EU',
    'NIST AI RMF': 'NIST',
    'ISO/IEC 42001': 'ISO',
  };
  return refs
    .map((r) => `${shortName[r.framework] ?? r.framework} ${r.items.map((i) => i.id).join(', ')}`)
    .join('  ·  ');
}

export function formatTerminal(findings: Finding[]): string {
  const lines: string[] = [];
  const summary = summarize(findings);
  const groups = groupByStatus(findings);

  // Per-finding dialect chip, shown only when the report mixes Terraform and
  // CloudFormation sources - a single-dialect report stays exactly as before.
  const dialects = new Set(
    findings.map((f) => sourceOfPath(f.filePath)).filter((s) => s !== undefined),
  );
  const mixedSources = dialects.size > 1;

  lines.push('');
  lines.push(chalk.bold('InfraRails — Compliance Report'));
  lines.push(chalk.dim('EU AI Act Article 12  ·  NIST AI RMF  ·  ISO/IEC 42001'));
  lines.push('');

  // Top-line summary
  lines.push(
    `${chalk.green(`${summary.pass} passed`)}   ${chalk.red(`${summary.fail} failed`)}   ${chalk.yellow(`${summary.warn} warnings`)}   ${chalk.magenta(`${summary.inconclusive} inconclusive`)}   ${chalk.gray(`${summary.skip} skipped`)}`
  );
  lines.push('');

  for (const status of STATUS_ORDER) {
    const items = groups.get(status)!;
    if (items.length === 0) continue;

    const color = statusColor(status);
    lines.push(color(chalk.bold(`- ${status} (${items.length}) -`)));
    lines.push('');

    for (const f of items) {
      const icon = statusIcon(f.status);
      const location = f.filePath
        ? `${f.filePath}${f.line ? `:${f.line}` : ''}`
        : '';

      const sourceChip = mixedSources
        ? (() => {
            const dialect = sourceOfPath(f.filePath);
            return dialect ? `${chalk.dim(`[${dialect}]`)} ` : '';
          })()
        : '';
      lines.push(`${icon} ${chalk.bold(f.ruleId)}  ${sourceChip}${f.description}`);
      if (location) lines.push(`   ${chalk.dim(location)}`);
      if (f.remediation) lines.push(`   ${chalk.cyan('→')} ${f.remediation}`);

      const refs = findingRefs(f);
      if (refs.length > 0) lines.push(`   ${chalk.dim(compactRefLine(refs))}`);
      lines.push('');
    }
  }

  if (summary.inconclusive > 0) {
    lines.push(
      chalk.dim(
        'Note: INCONCLUSIVE = could not verify statically (variables, SSM, module outputs).\n' +
        '      For audit-grade evidence run against `terraform show -json`.'
      )
    );
    lines.push('');
  }

  lines.push(chalk.dim(
    'Disclaimer: This report reflects the findings of an automated static analysis of your AWS AI\n' +
    'infrastructure configuration against selected controls from the EU AI Act, NIST AI RMF, and\n' +
    'ISO/IEC 42001. A passing result indicates that the scanned infrastructure-as-code configuration satisfies\n' +
    'the specific infrastructure-layer prerequisite checked - it does not constitute compliance with\n' +
    'any of these frameworks, nor does it substitute for a formal audit, certification, or conformity\n' +
    'assessment conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and\n' +
    'ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the\n' +
    'scope of infrastructure scanning. This report should be treated as a pre-audit readiness input,\n' +
    'not an attestation of conformance.'
  ));
  lines.push('');

  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────────────
// JSON
// ─────────────────────────────────────────────────────────────────────

export function formatJson(findings: Finding[]): string {
  const summary = summarize(findings);
  // Enrich each finding with a structured `frameworks` array so GRC tooling
  // (Drata, Vanta, ServiceNow GRC, OneTrust) consumes pre-parsed control IDs
  // instead of regexing the freeform reference strings. Raw strings are kept
  // for backwards compatibility.
  const enriched = findings.map((f) => ({
    ...f,
    frameworks: findingRefs(f),
  }));
  return JSON.stringify({ summary, findings: enriched }, null, 2);
}

// ─────────────────────────────────────────────────────────────────────
// SARIF 2.1.0
// ─────────────────────────────────────────────────────────────────────
//
// SARIF (Static Analysis Results Interchange Format, OASIS standard) is the
// lingua franca for static-analysis output. GitHub Code Scanning, Azure DevOps,
// GitLab, and the VS Code SARIF Viewer ingest it directly — uploading a SARIF
// file to GitHub via `github/codeql-action/upload-sarif` surfaces findings
// inline on PRs and in the repo's Security tab.

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const TOOL_NAME = 'infrarails';
const TOOL_VERSION = '0.2.1';
const TOOL_INFO_URI = 'https://github.com/vbalaji/infrarails';

type SarifLevel = 'none' | 'note' | 'warning' | 'error';
type SarifKind = 'pass' | 'fail' | 'review' | 'notApplicable' | 'informational';

// Status maps to two orthogonal SARIF fields:
//   - kind  = the audit verdict (pass / fail / review / notApplicable)
//   - level = the severity GitHub Code Scanning uses to colour the alert
// INCONCLUSIVE → kind=review (SARIF's "needs human verification" bucket)
// SKIP → kind=notApplicable so it does not show up as an alert.
function sarifLevel(status: FindingStatus): SarifLevel {
  switch (status) {
    case 'FAIL': return 'error';
    case 'WARN': return 'warning';
    case 'INCONCLUSIVE': return 'warning';
    case 'PASS': return 'none';
    case 'SKIP': return 'none';
  }
}

function sarifKind(status: FindingStatus): SarifKind {
  switch (status) {
    case 'PASS': return 'pass';
    case 'FAIL': return 'fail';
    case 'WARN': return 'fail';
    case 'INCONCLUSIVE': return 'review';
    case 'SKIP': return 'notApplicable';
  }
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId?: string };
    region?: { startLine: number };
  };
  properties?: Record<string, unknown>;
}

// `%SRCROOT%` is the de-facto SARIF uriBaseId for "checkout root", honoured by
// GitHub Code Scanning, CodeQL, and Microsoft's SARIF reference. Declared
// once on each run via originalUriBaseIds; referenced from synthetic
// locations whose URI must anchor to *something* GitHub can resolve.
const SARIF_SRCROOT = '%SRCROOT%';

// SARIF locations for a Finding. Three input shapes, one output contract
// (every result has >=1 location, every URI is GitHub-resolvable):
//
//   1. Real .tf path  → emit verbatim. Preserves the absolute/relative path
//      shape that upload-sarif already normalises today.
//   2. `plan:<addr>`  → plan-only resource with no on-disk HCL. Emit a
//      synthetic %SRCROOT% location so GitHub accepts the result; stash the
//      original plan address in properties.planAddress so the citation is
//      not lost.
//   3. empty string   → tree-wide finding (PASS/SKIP/INCONCLUSIVE for "no
//      Bedrock in tree", "plan does not destroy any resources", etc.). Same
//      synthetic %SRCROOT% location.
//
// Background: GitHub Code Scanning's upload-sarif rejects unknown URI schemes
// (silently strips the location) and refuses results with zero locations
// ("locationFromSarifResult: expected at least one location"). Both failure
// modes drop findings on the floor. The synthetic-location fallback surfaces
// them at directory level instead.
function sarifLocations(f: Finding): SarifLocation[] {
  if (!f.filePath || f.filePath.startsWith('plan:')) {
    const loc: SarifLocation = {
      physicalLocation: {
        artifactLocation: { uri: '.', uriBaseId: SARIF_SRCROOT },
      },
    };
    if (f.filePath?.startsWith('plan:')) {
      loc.properties = { planAddress: f.filePath.slice('plan:'.length) };
    }
    return [loc];
  }
  const loc: SarifLocation = {
    physicalLocation: { artifactLocation: { uri: f.filePath } },
  };
  if (f.line && f.line > 0) {
    loc.physicalLocation.region = { startLine: f.line };
  }
  return [loc];
}

// Compose the message text. SARIF clients usually display message.text inline
// on the finding row, so we fold the description + remediation into a single
// readable string instead of relying on properties bag.
function sarifMessage(f: Finding): string {
  if (f.remediation) return `${f.description}\n\nRemediation: ${f.remediation}`;
  return f.description;
}

// Stable per-finding fingerprint so GitHub Code Scanning can correlate the
// same alert across re-runs even when line numbers shift slightly.
function partialFingerprints(f: Finding): Record<string, string> {
  return {
    'ruleId/v1': f.ruleId,
    'location/v1': `${f.filePath ?? ''}:${f.line ?? ''}`,
  };
}

export function formatSarif(findings: Finding[]): string {
  // Build the rules section from the canonical rule registry so every rule
  // is described, not just ones with findings in this run. Ordered scanners
  // (CodeQL, ESLint, Semgrep) all do this — it gives consumers a stable
  // catalogue of what the tool can find.
  const rules = allRules.map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: r.description },
    fullDescription: { text: r.description },
    helpUri: TOOL_INFO_URI,
    defaultConfiguration: {
      level: r.severity === 'FAIL' ? 'error' : 'warning',
    },
    properties: {
      regulatoryReference: r.regulatoryReference,
      ...(r.nistReference ? { nistReference: r.nistReference } : {}),
      ...(r.isoReference ? { isoReference: r.isoReference } : {}),
      tags: ['compliance', 'eu-ai-act', 'nist-ai-rmf', 'iso-42001'],
    },
  }));

  const ruleIndexById = new Map(allRules.map((r, i) => [r.id, i]));

  const results = findings.map((f) => {
    const result: Record<string, unknown> = {
      ruleId: f.ruleId,
      level: sarifLevel(f.status),
      kind: sarifKind(f.status),
      message: { text: sarifMessage(f) },
      locations: sarifLocations(f),
      partialFingerprints: partialFingerprints(f),
      properties: {
        status: f.status,
        ...(f.regulatoryReference
          ? { regulatoryReference: f.regulatoryReference }
          : {}),
        ...(f.nistReference ? { nistReference: f.nistReference } : {}),
        ...(f.isoReference ? { isoReference: f.isoReference } : {}),
        frameworks: findingRefs(f),
        ...(f.unresolvedReason
          ? { unresolvedReason: f.unresolvedReason }
          : {}),
        ...(f.remediation ? { remediation: f.remediation } : {}),
      },
    };
    const idx = ruleIndexById.get(f.ruleId);
    if (idx !== undefined) result.ruleIndex = idx;
    // Invariant: every result must carry >=1 location or GitHub Code
    // Scanning drops it with "expected at least one location". Throw rather
    // than ship rejected SARIF.
    if (!Array.isArray(result.locations) || (result.locations as unknown[]).length < 1) {
      throw new Error(
        `SARIF emitter produced a result with no locations for ruleId=${f.ruleId}; ` +
          `every result must carry at least one location.`,
      );
    }
    return result;
  });

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: TOOL_INFO_URI,
            rules,
          },
        },
        // GitHub Code Scanning anchors uriBaseId-bearing relative URIs against
        // the checkout root via the %SRCROOT% sentinel; the literal `file:///`
        // value is symbolic and ignored by GitHub but required by the SARIF
        // spec to make originalUriBaseIds entries well-formed.
        originalUriBaseIds: {
          [SARIF_SRCROOT]: { uri: 'file:///' },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

// ─────────────────────────────────────────────────────────────────────
// HTML
// ─────────────────────────────────────────────────────────────────────

// Inline brand mark (rails + brass check), matching infrarails.com. Two
// variants: white rails on the dark masthead, navy rails for the light footer.
const LOGO_SVG_DARK =
  `<svg viewBox="0 0 32 32" width="24" height="24" aria-hidden="true">` +
  `<path d="M4 12h24M4 19h24" stroke="#ffffff" stroke-width="2.4" stroke-linecap="round" opacity="0.45" fill="none"/>` +
  `<path d="M9 16.5l5 5 9.5-11" stroke="#c9a14a" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>` +
  `</svg>`;
const LOGO_SVG_BRASS =
  `<svg viewBox="0 0 32 32" width="20" height="20" aria-hidden="true">` +
  `<path d="M4 12h24M4 19h24" stroke="#0c2d52" stroke-width="2.4" stroke-linecap="round" opacity="0.4" fill="none"/>` +
  `<path d="M9 16.5l5 5 9.5-11" stroke="#b08a38" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>` +
  `</svg>`;

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function statusClass(status: FindingStatus): string {
  return status.toLowerCase();
}

function frameworkSlug(framework: string): string {
  if (framework === 'EU AI Act') return 'eu';
  if (framework === 'NIST AI RMF') return 'nist';
  if (framework === 'ISO/IEC 42001') return 'iso';
  return 'other';
}

function renderFindingCard(f: Finding): string {
  const cls = statusClass(f.status);
  const location = f.filePath
    ? `<span class="location">${escapeHtml(f.filePath)}${f.line ? `:${f.line}` : ''}</span>`
    : '';
  const remediation = f.remediation
    ? `<p class="remediation"><span class="arrow">&rarr;</span> ${escapeHtml(f.remediation)}</p>`
    : '';

  const refs = findingRefs(f);
  const refPills = refs
    .map((r) => {
      const slug = frameworkSlug(r.framework);
      const pills = r.items
        .map((i) => {
          const tooltip = i.desc ? ` title="${escapeHtml(i.desc)}"` : '';
          return `<span class="pill ${slug}"${tooltip}>${escapeHtml(i.id)}</span>`;
        })
        .join('');
      return `<span class="ref-group"><span class="fw-label">${escapeHtml(r.framework)}</span>${pills}</span>`;
    })
    .join('');

  return `      <article class="finding ${cls}">
        <div class="finding-head">
          <span class="status-pill ${cls}">${f.status}</span>
          <span class="rule-id">${escapeHtml(f.ruleId)}</span>
          ${location}
        </div>
        <p class="description">${escapeHtml(f.description)}</p>
        ${remediation}
        <div class="refs">${refPills}</div>
      </article>`;
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  FAIL: 'Failures - fix these',
  WARN: 'Warnings',
  INCONCLUSIVE: 'Inconclusive - verify manually',
  PASS: 'Passing',
  SKIP: 'Skipped (not applicable)',
};

export function formatHtml(findings: Finding[]): string {
  const summary = summarize(findings);
  const groups = groupByStatus(findings);
  const generatedAt =
    new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  const sections = STATUS_ORDER
    .map((status) => {
      const items = groups.get(status)!;
      if (items.length === 0) return '';
      const cls = statusClass(status);
      const cards = items.map(renderFindingCard).join('\n');
      // Default-collapse PASS and SKIP - they're not what you came here for.
      const open = status === 'PASS' || status === 'SKIP' ? '' : ' open';
      return `      <details class="group ${cls}"${open}>
        <summary>
          <span class="dot ${cls}"></span>
          <span class="group-label">${STATUS_LABELS[status]}</span>
          <span class="group-count">${items.length}</span>
        </summary>
${cards}
      </details>`;
    })
    .filter(Boolean)
    .join('\n');

  const note = summary.inconclusive > 0
    ? `<p class="note"><strong>About INCONCLUSIVE:</strong> the scanner could not verify these statically - typically because of variables without defaults, SSM parameters, or module outputs. For audit-grade evidence, run against <code>terraform show -json</code>.</p>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Infrarails Compliance Report</title>
<style>
  :root {
    /* Brand (matches infrarails.com): navy + brass + white */
    --navy: #0c2d52; --navy-deep: #081f3a; --navy-soft: #2b5586;
    --brass: #c9a14a; --brass-dark: #9a7d2f;
    --ink: #1c2733; --muted: #5a6b7d;
    --tint: #f3f6fa; --line: #d8e1ec; --card: #ffffff;
    /* Semantic verdict colours, tuned to sit beside the brand palette */
    --pass: #1f9d57; --fail: #c8362f; --warn: #c98a1e;
    --inconclusive: #5b53b5; --skip: #7a8896;
    /* Framework accents, kept on-brand (navy / steel / brass) */
    --eu: #0c2d52; --nist: #2b5586; --iso: #8a6d22;
    --serif: Georgia, "Times New Roman", serif;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: "SF Mono", SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body {
    font-family: var(--sans); font-size: 15px; line-height: 1.6;
    background: var(--tint); color: var(--ink); margin: 0;
  }

  /* ---------- branded header band ---------- */
  .masthead {
    background: linear-gradient(180deg, var(--navy) 0%, var(--navy-deep) 100%);
    color: #fff; padding: 30px 0 56px;
  }
  .container { max-width: 880px; margin: 0 auto; padding: 0 28px; }
  .brandrow {
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; flex-wrap: wrap;
    border-bottom: 1px solid rgba(255,255,255,.14);
    padding-bottom: 16px; margin-bottom: 22px;
  }
  .wordmark { display: inline-flex; align-items: center; gap: 9px;
    font-family: var(--serif); font-size: 1.3rem; font-weight: bold;
    letter-spacing: .01em; }
  .wm-rails { color: var(--brass); }
  .masthead .meta { font-size: .82rem; color: rgba(255,255,255,.66);
    font-variant-numeric: tabular-nums; }
  .masthead h1 {
    font-family: var(--serif); font-weight: normal;
    font-size: clamp(1.7rem, 4vw, 2.3rem); line-height: 1.15; margin: 0;
  }
  .masthead .subtitle { color: rgba(255,255,255,.74);
    font-size: .92rem; margin: 10px 0 0; }

  main { padding: 28px 0 56px; }

  /* ---------- summary scorecard ---------- */
  .summary-bar {
    display: grid; grid-template-columns: repeat(5, 1fr);
    background: var(--card); border: 1px solid var(--line);
    border-radius: 10px; padding: 6px; margin: -38px 0 28px;
    box-shadow: 0 6px 24px rgba(8, 31, 58, .10);
  }
  .summary-bar .stat {
    display: flex; flex-direction: column; align-items: center;
    padding: 14px 8px; border-radius: 7px; text-align: center;
  }
  .summary-bar .stat + .stat { border-left: 1px solid var(--line); }
  .summary-bar .count { font-size: 1.9rem; font-weight: 700; line-height: 1;
    font-variant-numeric: tabular-nums; }
  .summary-bar .label { color: var(--muted); font-size: .78rem;
    text-transform: uppercase; letter-spacing: .05em; margin-top: 7px; }
  .stat.pass .count { color: var(--pass); }
  .stat.fail .count { color: var(--fail); }
  .stat.warn .count { color: var(--warn); }
  .stat.inconclusive .count { color: var(--inconclusive); }
  .stat.skip .count { color: var(--skip); }

  /* ---------- grouped sections ---------- */
  details.group {
    background: var(--card); border: 1px solid var(--line);
    border-radius: 10px; margin-bottom: 14px; overflow: hidden;
  }
  details.group > summary {
    list-style: none; cursor: pointer; padding: 15px 20px;
    display: flex; align-items: center; gap: 12px; user-select: none;
  }
  details.group > summary:hover { background: var(--tint); }
  details.group > summary::-webkit-details-marker { display: none; }
  details.group > summary::after {
    content: '\\25B8'; color: var(--muted); transition: transform .15s;
    margin-left: 4px;
  }
  details.group[open] > summary::after { transform: rotate(90deg); }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .dot.pass { background: var(--pass); }
  .dot.fail { background: var(--fail); }
  .dot.warn { background: var(--warn); }
  .dot.skip { background: var(--skip); }
  .dot.inconclusive { background: var(--inconclusive); }
  .group-label { font-weight: 600; flex: 1; color: var(--navy); }
  .group-count {
    background: var(--tint); color: var(--muted); border: 1px solid var(--line);
    padding: .12rem .6rem; border-radius: 999px; font-size: .8rem; font-weight: 700;
    font-variant-numeric: tabular-nums;
  }

  /* ---------- finding cards ---------- */
  .finding { border-top: 1px solid var(--line); padding: 16px 20px 16px 22px;
    position: relative; }
  .finding::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0;
    width: 3px; }
  .finding.fail::before { background: var(--fail); }
  .finding.warn::before { background: var(--warn); }
  .finding.inconclusive::before { background: var(--inconclusive); }
  .finding.pass::before { background: var(--pass); }
  .finding.skip::before { background: var(--skip); }
  .finding-head { display: flex; align-items: center; gap: 10px;
    flex-wrap: wrap; margin-bottom: 6px; }
  .status-pill {
    font-size: .64rem; font-weight: 700; letter-spacing: .06em;
    padding: .2rem .5rem; border-radius: 4px; color: #fff;
  }
  .status-pill.pass { background: var(--pass); }
  .status-pill.fail { background: var(--fail); }
  .status-pill.warn { background: var(--warn); }
  .status-pill.skip { background: var(--skip); }
  .status-pill.inconclusive { background: var(--inconclusive); }
  .rule-id { font-family: var(--mono); font-weight: 600; font-size: .82rem;
    color: var(--navy); background: var(--tint); border: 1px solid var(--line);
    border-radius: 4px; padding: .1rem .45rem; }
  .location { font-family: var(--mono); font-size: .74rem; color: var(--muted);
    margin-left: auto; }
  .description { margin: .3rem 0; color: var(--ink); }
  .remediation {
    background: #f0f8f2; border-left: 3px solid var(--pass);
    padding: .6rem .8rem; margin: .6rem 0 .2rem; border-radius: 0 6px 6px 0;
    font-size: .9rem;
  }
  .remediation .arrow { color: var(--pass); font-weight: 700; margin-right: .4rem; }

  .refs { display: flex; flex-wrap: wrap; gap: .55rem .9rem;
    margin-top: .7rem; align-items: center; }
  .ref-group { display: inline-flex; align-items: center; gap: .35rem; flex-wrap: wrap; }
  .fw-label { font-size: .66rem; color: var(--muted); text-transform: uppercase;
    letter-spacing: .05em; font-weight: 700; }
  .pill {
    font-family: var(--mono); font-size: .71rem; padding: .12rem .45rem;
    border-radius: 4px; cursor: help; border: 1px solid;
  }
  .pill.eu { background: #eef3f9; color: var(--eu); border-color: #c3d3e6; }
  .pill.nist { background: #eef3f9; color: var(--nist); border-color: #c3d3e6; }
  .pill.iso { background: #faf4e6; color: var(--iso); border-color: #ead7ad; }

  .note {
    background: #f0eff8; border-left: 3px solid var(--inconclusive);
    padding: .8rem 1rem; margin-top: 22px; border-radius: 0 6px 6px 0;
    font-size: .85rem; color: #38336b;
  }
  .disclaimer {
    border-top: 1px solid var(--line); margin-top: 36px; padding-top: 18px;
    font-size: .76rem; color: var(--muted); line-height: 1.65;
  }
  .disclaimer strong { display: block; margin-bottom: .3rem; color: var(--navy);
    font-family: var(--serif); font-size: .92rem; }
  .brandfoot { display: flex; align-items: center; gap: 8px; margin-bottom: 12px;
    color: var(--navy); font-family: var(--serif); font-weight: bold; font-size: 1rem; }
  .brandfoot .wm-rails { color: var(--brass-dark); }
  code { font-family: var(--mono); background: var(--tint);
    border: 1px solid var(--line); padding: .08em .35em; border-radius: 3px;
    font-size: .9em; }

  @media print {
    body { background: #fff; font-size: 12px; }
    .masthead { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .summary-bar { box-shadow: none; }
    details.group { page-break-inside: avoid; }
    details.group:not([open]) { display: none; }
    .pill { cursor: default; }
  }
</style>
</head>
<body>
  <header class="masthead">
    <div class="container">
      <div class="brandrow">
        <span class="wordmark">${LOGO_SVG_DARK}<span>Infra<span class="wm-rails">rails</span></span></span>
        <span class="meta">${escapeHtml(generatedAt)} &middot; ${summary.total} findings</span>
      </div>
      <h1>Compliance Report</h1>
      <p class="subtitle">EU AI Act &middot; NIST AI RMF &middot; ISO/IEC 42001</p>
    </div>
  </header>

  <main>
    <div class="container">
      <div class="summary-bar">
        <div class="stat fail"><span class="count">${summary.fail}</span><span class="label">failed</span></div>
        <div class="stat warn"><span class="count">${summary.warn}</span><span class="label">warnings</span></div>
        <div class="stat inconclusive"><span class="count">${summary.inconclusive}</span><span class="label">inconclusive</span></div>
        <div class="stat pass"><span class="count">${summary.pass}</span><span class="label">passed</span></div>
        <div class="stat skip"><span class="count">${summary.skip}</span><span class="label">skipped</span></div>
      </div>

${sections}

      ${note}

      <div class="disclaimer">
        <div class="brandfoot">${LOGO_SVG_BRASS}<span>Infra<span class="wm-rails">rails</span></span></div>
        <strong>Disclaimer</strong>
        This report reflects the findings of an automated static analysis of your AWS AI infrastructure configuration against selected controls from the EU AI Act, NIST AI RMF, and ISO/IEC 42001. A passing result indicates that the scanned infrastructure-as-code configuration satisfies the specific infrastructure-layer prerequisite checked - it does not constitute compliance with any of these frameworks, nor does it substitute for a formal audit, certification, or conformity assessment conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the scope of infrastructure scanning. This report should be treated as a pre-audit readiness input, not an attestation of conformance.
      </div>
    </div>
  </main>
</body>
</html>
`;
}

// ─────────────────────────────────────────────────────────────────────
// PDF
// ─────────────────────────────────────────────────────────────────────

// Pure-JS PDF generation via pdfkit - no Chromium, no system libraries.
// We do NOT reuse formatHtml here because the only way to render HTML to PDF
// without a browser is to ship one. Instead we draw the report procedurally
// using pdfkit's primitives (text, rectangles, rounded pills) - the layout is
// simpler than the HTML version but matches the same visual language: status
// pills, framework-coloured ref pills, and grouped sections.

// Brand palette (matches infrarails.com): navy + brass + white.
const PDF_NAVY = '#0c2d52';
const PDF_NAVY_DEEP = '#081f3a';
const PDF_BRASS = '#c9a14a';
const PDF_BRASS_DARK = '#9a7d2f';

const PDF_STATUS_COLORS: Record<FindingStatus, string> = {
  PASS: '#1f9d57',
  FAIL: '#c8362f',
  WARN: '#c98a1e',
  SKIP: '#7a8896',
  INCONCLUSIVE: '#5b53b5',
};

// Framework accents kept on-brand: navy / steel for EU & NIST, brass for ISO.
const PDF_FRAMEWORK_FG: Record<string, string> = {
  'EU AI Act': '#0c2d52',
  'NIST AI RMF': '#2b5586',
  'ISO/IEC 42001': '#8a6d22',
};
const PDF_FRAMEWORK_BG: Record<string, string> = {
  'EU AI Act': '#eef3f9',
  'NIST AI RMF': '#eef3f9',
  'ISO/IEC 42001': '#faf4e6',
};

const PDF_TEXT = '#1c2733';
const PDF_MUTED = '#5a6b7d';
const PDF_BORDER = '#d8e1ec';
const PDF_TINT = '#f3f6fa';
const PDF_REMEDIATION_BG = '#f0f8f2';

type PDFDoc = PDFKit.PDFDocument;

// Reserve vertical space; if it would overflow the current page, break first.
// This prevents orphaned section headers and split status pills.
function ensureRoom(doc: PDFDoc, needed: number) {
  const bottom = doc.page.height - doc.page.margins.bottom;
  if (doc.y + needed > bottom) doc.addPage();
}

function drawPill(
  doc: PDFDoc,
  x: number,
  y: number,
  text: string,
  bg: string,
  fg: string,
  fontSize = 7,
): number {
  doc.font('Helvetica-Bold').fontSize(fontSize);
  const padX = 4;
  const padY = 2;
  const textWidth = doc.widthOfString(text);
  const w = textWidth + padX * 2;
  const h = fontSize + padY * 2 + 1;
  doc.roundedRect(x, y, w, h, 2).fill(bg);
  doc.fillColor(fg).text(text, x + padX, y + padY, { lineBreak: false });
  return w;
}

// Draw the brand mark (two rails + brass check) at native scale, matching the
// inline SVG on infrarails.com. Stroked vector primitives only - no raster.
function drawLogoMark(
  doc: PDFDoc,
  x: number,
  y: number,
  size: number,
  railColor: string,
  railOpacity: number,
  checkColor: string,
) {
  const s = size / 32;
  doc.save();
  doc.lineCap('round').lineJoin('round');
  doc.lineWidth(2.4 * s).strokeColor(railColor).strokeOpacity(railOpacity);
  doc.moveTo(x + 4 * s, y + 12 * s).lineTo(x + 28 * s, y + 12 * s).stroke();
  doc.moveTo(x + 4 * s, y + 19 * s).lineTo(x + 28 * s, y + 19 * s).stroke();
  doc.strokeOpacity(1).lineWidth(3.2 * s).strokeColor(checkColor);
  doc
    .moveTo(x + 9 * s, y + 16.5 * s)
    .lineTo(x + 14 * s, y + 21.5 * s)
    .lineTo(x + 23.5 * s, y + 10.5 * s)
    .stroke();
  doc.restore();
}

// Full-bleed navy masthead with logo, wordmark, title and a brass accent rule.
// Leaves doc.y just above the band's lower edge so the summary scorecard can
// float over it, mirroring the website's overlapping hero/card composition.
function drawHeader(doc: PDFDoc, total: number, generatedAt: string) {
  const pageW = doc.page.width;
  const left = doc.page.margins.left;
  const right = pageW - doc.page.margins.right;
  const bandH = 118;

  doc.save();
  const grad = doc.linearGradient(0, 0, 0, bandH);
  grad.stop(0, PDF_NAVY).stop(1, PDF_NAVY_DEEP);
  doc.rect(0, 0, pageW, bandH).fill(grad);
  doc.restore();

  // Logo + wordmark, top-left.
  drawLogoMark(doc, left, 24, 22, '#ffffff', 0.45, PDF_BRASS);
  doc.font('Times-Bold').fontSize(15);
  doc.fillColor('#ffffff').text('Infra', left + 30, 28, {
    lineBreak: false,
    continued: true,
  });
  doc.fillColor(PDF_BRASS).text('rails', { lineBreak: false });

  // Run metadata, top-right on the same row.
  doc.font('Helvetica').fontSize(8.5).fillColor('#9fb3cc')
    .text(`${generatedAt}  ·  ${total} findings`, left, 31, {
      width: right - left,
      align: 'right',
      lineBreak: false,
    });

  // Title + framework subtitle.
  doc.font('Times-Bold').fontSize(24).fillColor('#ffffff')
    .text('Compliance Report', left, 50, { lineBreak: false });
  doc.font('Helvetica').fontSize(9.5).fillColor('#b9c8db')
    .text('EU AI Act  ·  NIST AI RMF  ·  ISO/IEC 42001', left, 81, {
      lineBreak: false,
    });

  // Brass accent rule along the band's lower edge.
  doc.rect(0, bandH - 2.5, pageW, 2.5).fill(PDF_BRASS);

  // Sit just above the edge so the scorecard overlaps the band, leaving
  // clearance below the subtitle so the card never covers it.
  doc.y = bandH - 12;
  doc.x = left;
}

function drawSummaryBar(doc: PDFDoc, s: ScanSummary) {
  const x = doc.page.margins.left;
  const y = doc.y;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const h = 58;

  doc.roundedRect(x, y, w, h, 8).fillAndStroke('#ffffff', PDF_BORDER);

  const stats: { count: number; label: string; color: string }[] = [
    { count: s.fail, label: 'FAILED', color: PDF_STATUS_COLORS.FAIL },
    { count: s.warn, label: 'WARNINGS', color: PDF_STATUS_COLORS.WARN },
    { count: s.inconclusive, label: 'INCONCLUSIVE', color: PDF_STATUS_COLORS.INCONCLUSIVE },
    { count: s.pass, label: 'PASSED', color: PDF_STATUS_COLORS.PASS },
    { count: s.skip, label: 'SKIPPED', color: PDF_STATUS_COLORS.SKIP },
  ];
  const cellW = w / stats.length;
  stats.forEach((st, i) => {
    const cx = x + i * cellW;
    // Hairline dividers between cells (not before the first).
    if (i > 0) {
      doc.strokeColor(PDF_BORDER).lineWidth(0.5)
        .moveTo(cx, y + 12).lineTo(cx, y + h - 12).stroke();
    }
    doc.font('Helvetica-Bold').fontSize(20).fillColor(st.color)
      .text(String(st.count), cx, y + 11, { width: cellW, align: 'center', lineBreak: false });
    doc.font('Helvetica-Bold').fontSize(7).fillColor(PDF_MUTED)
      .text(st.label, cx, y + 38, { width: cellW, align: 'center', lineBreak: false });
  });

  doc.y = y + h + 16;
  doc.x = doc.page.margins.left;
}

function drawSectionHeader(doc: PDFDoc, status: FindingStatus, count: number) {
  ensureRoom(doc, 40);
  const x = doc.page.margins.left;
  const y = doc.y;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const h = 26;
  const padX = 14;
  const color = PDF_STATUS_COLORS[status];

  // Light tint plate with a status-coloured accent bar on the left edge -
  // calmer than the old full-bleed colour fill, easier to scan a long report.
  doc.roundedRect(x, y, w, h, 5).fillAndStroke(PDF_TINT, PDF_BORDER);
  doc.save();
  doc.roundedRect(x, y, w, h, 5).clip();
  doc.rect(x, y, 4, h).fill(color);
  doc.restore();

  // Status dot.
  doc.circle(x + padX, y + h / 2, 3.5).fill(color);

  // Section label in navy.
  doc.font('Helvetica-Bold').fontSize(10).fillColor(PDF_NAVY)
    .text(STATUS_LABELS[status], x + padX + 10, y + 8, { lineBreak: false });

  // Count, right-aligned.
  doc.font('Helvetica-Bold').fontSize(10).fillColor(PDF_MUTED)
    .text(String(count), x, y + 8, { width: w - padX, align: 'right', lineBreak: false });

  doc.y = y + h + 12;
  doc.x = doc.page.margins.left;
}

function drawFinding(doc: PDFDoc, f: Finding) {
  const x = doc.page.margins.left;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;

  // Reserve a rough minimum so we don't split the head row across pages.
  ensureRoom(doc, 70);

  const headY = doc.y;
  // Status pill
  const pillW = drawPill(
    doc, x, headY, f.status, PDF_STATUS_COLORS[f.status], '#ffffff', 8,
  );
  // Rule ID (mono, navy) - right of the pill on the same row
  doc.font('Courier-Bold').fontSize(9).fillColor(PDF_NAVY)
    .text(f.ruleId, x + pillW + 6, headY + 2, { lineBreak: false });

  doc.y = headY + 16;
  doc.x = x;

  // File location on its own line below the head row. Long paths (deep
  // monorepos, absolute paths) used to right-align across the full width and
  // collide with the rule ID; giving them their own line and the full content
  // width lets them wrap cleanly.
  if (f.filePath) {
    doc.moveDown(0.2);
    const loc = `${f.filePath}${f.line ? `:${f.line}` : ''}`;
    doc.font('Courier').fontSize(8).fillColor(PDF_MUTED)
      .text(loc, x, doc.y, { width: w });
    doc.moveDown(0.5);
  }

  // Description
  doc.font('Helvetica').fontSize(9.5).fillColor(PDF_TEXT)
    .text(f.description, x, doc.y, { width: w });
  doc.moveDown(0.5);

  // Remediation block
  if (f.remediation) {
    const remY = doc.y;
    const remPadX = 8;
    const remPadY = 6;
    doc.font('Helvetica').fontSize(9).fillColor(PDF_TEXT);
    const remHeight = doc.heightOfString(f.remediation, {
      width: w - remPadX * 2 - 12,
    }) + remPadY * 2;
    ensureRoom(doc, remHeight + 4);
    const ry = doc.y;
    doc.rect(x, ry, w, remHeight).fill(PDF_REMEDIATION_BG);
    doc.rect(x, ry, 3, remHeight).fill(PDF_STATUS_COLORS.PASS);
    doc.fillColor(PDF_STATUS_COLORS.PASS).font('Helvetica-Bold').fontSize(10)
      .text('→', x + remPadX, ry + remPadY - 1, { lineBreak: false });
    doc.font('Helvetica').fontSize(9).fillColor(PDF_TEXT)
      .text(f.remediation, x + remPadX + 12, ry + remPadY, {
        width: w - remPadX * 2 - 12,
      });
    doc.y = ry + remHeight + 4;
    doc.x = x;
  }

  // Refs - framework label + colored pills per item
  const refs = findingRefs(f);
  if (refs.length > 0) {
    let cx = x;
    let cy = doc.y;
    const lineH = 14;
    for (const r of refs) {
      // Framework label
      doc.font('Helvetica-Bold').fontSize(7).fillColor(PDF_MUTED);
      const labelText = r.framework.toUpperCase();
      const labelW = doc.widthOfString(labelText);
      if (cx + labelW + 6 > x + w) { cx = x; cy += lineH; }
      doc.text(labelText, cx, cy + 3, { lineBreak: false });
      cx += labelW + 4;
      // Pills
      for (const item of r.items) {
        const fg = PDF_FRAMEWORK_FG[r.framework] ?? PDF_TEXT;
        const bg = PDF_FRAMEWORK_BG[r.framework] ?? '#f3f4f6';
        doc.font('Helvetica-Bold').fontSize(7);
        const pw = doc.widthOfString(item.id) + 8;
        if (cx + pw > x + w) { cx = x; cy += lineH; }
        drawPill(doc, cx, cy, item.id, bg, fg, 7);
        cx += pw + 4;
      }
      cx += 8;
    }
    doc.y = cy + lineH;
    doc.x = x;
  }

  // Card separator with breathing room above and below so findings do not
  // visually run together.
  doc.moveDown(0.5);
  const sepY = doc.y;
  doc.strokeColor(PDF_BORDER).lineWidth(0.5)
    .moveTo(x, sepY).lineTo(x + w, sepY).stroke();
  doc.y = sepY + 12;
}

function drawDisclaimer(doc: PDFDoc) {
  ensureRoom(doc, 90);
  const x = doc.page.margins.left;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const text =
    'This report reflects the findings of an automated static analysis of your AWS AI infrastructure ' +
    'configuration against selected controls from the EU AI Act, NIST AI RMF, and ISO/IEC 42001. ' +
    'A passing result indicates that the scanned infrastructure-as-code configuration satisfies the specific ' +
    'infrastructure-layer prerequisite checked - it does not constitute compliance with any of these ' +
    'frameworks, nor does it substitute for a formal audit, certification, or conformity assessment ' +
    'conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 ' +
    'requires organisational, procedural, and governance measures that are outside the scope of ' +
    'infrastructure scanning. This report should be treated as a pre-audit readiness input, not an ' +
    'attestation of conformance.';

  doc.moveDown(0.8);
  // Brand sign-off above a hairline rule.
  const brandY = doc.y;
  drawLogoMark(doc, x, brandY - 1, 16, PDF_NAVY, 0.4, PDF_BRASS_DARK);
  doc.font('Times-Bold').fontSize(11);
  doc.fillColor(PDF_NAVY).text('Infra', x + 22, brandY, {
    lineBreak: false,
    continued: true,
  });
  doc.fillColor(PDF_BRASS_DARK).text('rails', { lineBreak: false });

  const ruleY = brandY + 20;
  doc.strokeColor(PDF_BORDER).lineWidth(0.5)
    .moveTo(x, ruleY).lineTo(x + w, ruleY).stroke();

  const y = ruleY + 10;
  doc.font('Times-Bold').fontSize(10).fillColor(PDF_NAVY)
    .text('Disclaimer', x, y, { lineBreak: false });
  doc.font('Helvetica').fontSize(8).fillColor(PDF_MUTED)
    .text(text, x, y + 16, { width: w });
  doc.y = doc.y + 4;
}

export async function formatPdf(findings: Finding[]): Promise<Buffer> {
  let PDFDocument: typeof import('pdfkit');
  try {
    const mod = await import('pdfkit');
    PDFDocument = (mod as { default?: typeof import('pdfkit') }).default ?? mod;
  } catch {
    throw new Error(
      'PDF output requires pdfkit. Install it with: npm install pdfkit',
    );
  }

  const doc = new (PDFDocument as unknown as new (opts: object) => PDFDoc)({
    size: 'A4',
    margin: 50,
    info: {
      Title: 'Infrarails Compliance Report',
      Producer: 'infrarails',
      Author: 'Infrarails',
    },
  });

  const chunks: Buffer[] = [];
  doc.on('data', (c: Buffer) => chunks.push(c));
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });

  const summary = summarize(findings);
  const groups = groupByStatus(findings);
  const generatedAt =
    new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  drawHeader(doc, summary.total, generatedAt);
  drawSummaryBar(doc, summary);

  for (const status of STATUS_ORDER) {
    const items = groups.get(status)!;
    if (items.length === 0) continue;
    drawSectionHeader(doc, status, items.length);
    for (const f of items) drawFinding(doc, f);
    doc.moveDown(0.3);
  }

  drawDisclaimer(doc);

  doc.end();
  return done;
}
