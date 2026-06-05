import chalk from 'chalk';
import { Finding, FindingStatus } from './types';
import { allRules } from './rules';

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

      lines.push(`${icon} ${chalk.bold(f.ruleId)}  ${f.description}`);
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
    'ISO/IEC 42001. A passing result indicates that the scanned Terraform configuration satisfies\n' +
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
      return `    <details class="group ${cls}"${open}>
      <summary>
        <span class="group-status ${cls}">${status}</span>
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
<title>InfraRails — Compliance Report</title>
<style>
  :root {
    --pass: #16a34a; --fail: #dc2626; --warn: #d97706;
    --skip: #6b7280; --inconclusive: #9333ea;
    --bg: #f8fafc; --card: #ffffff; --border: #e5e7eb;
    --text: #111827; --muted: #6b7280;
    --eu: #1e40af; --nist: #0f766e; --iso: #7e22ce;
  }
  * { box-sizing: border-box; }
  body {
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    margin: 0; padding: 2rem 1rem;
  }
  .container { max-width: 880px; margin: 0 auto; }
  header.top { margin-bottom: 1.5rem; }
  header.top h1 { font-size: 1.5rem; margin: 0; }
  header.top .subtitle { color: var(--muted); margin: .25rem 0 0; font-size: .9rem; }
  header.top .meta { color: var(--muted); font-size: .8rem; margin-top: .5rem; }

  .summary-bar {
    display: flex; flex-wrap: wrap; gap: 1.25rem;
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem;
  }
  .summary-bar .stat { display: flex; align-items: baseline; gap: .4rem; }
  .summary-bar .count { font-size: 1.5rem; font-weight: 700; }
  .summary-bar .label { color: var(--muted); font-size: .85rem; }
  .stat.pass .count { color: var(--pass); }
  .stat.fail .count { color: var(--fail); }
  .stat.warn .count { color: var(--warn); }
  .stat.inconclusive .count { color: var(--inconclusive); }
  .stat.skip .count { color: var(--skip); }

  details.group {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 1rem; overflow: hidden;
  }
  details.group > summary {
    list-style: none; cursor: pointer; padding: .85rem 1.25rem;
    display: flex; align-items: center; gap: .75rem;
    user-select: none;
  }
  details.group > summary::-webkit-details-marker { display: none; }
  details.group > summary::before {
    content: '\\25B8'; color: var(--muted); transition: transform .15s;
    display: inline-block; width: 1rem;
  }
  details.group[open] > summary::before { transform: rotate(90deg); }
  .group-status {
    font-size: .7rem; font-weight: 700; letter-spacing: .05em;
    padding: .2rem .55rem; border-radius: 4px; color: #fff;
  }
  .group-status.pass { background: var(--pass); }
  .group-status.fail { background: var(--fail); }
  .group-status.warn { background: var(--warn); }
  .group-status.skip { background: var(--skip); }
  .group-status.inconclusive { background: var(--inconclusive); }
  .group-label { font-weight: 600; flex: 1; }
  .group-count {
    background: #f3f4f6; color: var(--muted);
    padding: .15rem .55rem; border-radius: 999px; font-size: .8rem; font-weight: 600;
  }

  .finding {
    border-top: 1px solid var(--border);
    padding: 1rem 1.25rem;
  }
  .finding-head { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; margin-bottom: .35rem; }
  .status-pill {
    font-size: .65rem; font-weight: 700; letter-spacing: .05em;
    padding: .15rem .45rem; border-radius: 3px; color: #fff;
  }
  .status-pill.pass { background: var(--pass); }
  .status-pill.fail { background: var(--fail); }
  .status-pill.warn { background: var(--warn); }
  .status-pill.skip { background: var(--skip); }
  .status-pill.inconclusive { background: var(--inconclusive); }
  .rule-id {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-weight: 600; font-size: .85rem;
  }
  .location {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: .75rem; color: var(--muted); margin-left: auto;
  }
  .description { margin: .35rem 0; }
  .remediation {
    background: #ecfdf5; border-left: 3px solid var(--pass);
    padding: .55rem .75rem; margin: .5rem 0; border-radius: 4px;
    font-size: .9rem;
  }
  .remediation .arrow { color: var(--pass); font-weight: 700; margin-right: .35rem; }

  .refs {
    display: flex; flex-wrap: wrap; gap: .65rem .85rem;
    margin-top: .65rem; align-items: center;
  }
  .ref-group { display: inline-flex; align-items: center; gap: .3rem; flex-wrap: wrap; }
  .fw-label { font-size: .7rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }
  .pill {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: .72rem; padding: .12rem .45rem;
    border-radius: 3px; cursor: help;
    border: 1px solid;
  }
  .pill.eu { background: #eff6ff; color: var(--eu); border-color: #bfdbfe; }
  .pill.nist { background: #f0fdfa; color: var(--nist); border-color: #99f6e4; }
  .pill.iso { background: #faf5ff; color: var(--iso); border-color: #e9d5ff; }

  .note {
    background: #faf5ff; border-left: 3px solid var(--inconclusive);
    padding: .75rem 1rem; margin-top: 1.5rem; border-radius: 4px;
    font-size: .85rem; color: #4b1d6f;
  }
  .disclaimer {
    background: #f8fafc; border: 1px solid var(--border); border-radius: 6px;
    padding: .85rem 1rem; margin-top: 2rem;
    font-size: .78rem; color: var(--muted); line-height: 1.6;
  }
  .disclaimer strong { display: block; margin-bottom: .25rem; color: var(--text); }
  code { background: #f3f4f6; padding: .1rem .3rem; border-radius: 3px; font-size: .9em; }

  @media print {
    body { background: #fff; padding: 0; font-size: 12px; }
    details.group { box-shadow: none; page-break-inside: avoid; }
    details.group:not([open]) { display: none; }
    .pill { cursor: default; }
  }
</style>
</head>
<body>
<div class="container">
  <header class="top">
    <h1>InfraRails — Compliance Report</h1>
    <p class="subtitle">EU AI Act Article 12 &middot; NIST AI RMF &middot; ISO/IEC 42001</p>
    <p class="meta">${escapeHtml(generatedAt)} &middot; ${summary.total} findings</p>
  </header>

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
    <strong>Disclaimer</strong>
    This report reflects the findings of an automated static analysis of your AWS AI infrastructure configuration against selected controls from the EU AI Act, NIST AI RMF, and ISO/IEC 42001. A passing result indicates that the scanned Terraform configuration satisfies the specific infrastructure-layer prerequisite checked - it does not constitute compliance with any of these frameworks, nor does it substitute for a formal audit, certification, or conformity assessment conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the scope of infrastructure scanning. This report should be treated as a pre-audit readiness input, not an attestation of conformance.
  </div>
</div>
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

const PDF_STATUS_COLORS: Record<FindingStatus, string> = {
  PASS: '#16a34a',
  FAIL: '#dc2626',
  WARN: '#d97706',
  SKIP: '#6b7280',
  INCONCLUSIVE: '#9333ea',
};

const PDF_FRAMEWORK_FG: Record<string, string> = {
  'EU AI Act': '#1e40af',
  'NIST AI RMF': '#0f766e',
  'ISO/IEC 42001': '#7e22ce',
};
const PDF_FRAMEWORK_BG: Record<string, string> = {
  'EU AI Act': '#eff6ff',
  'NIST AI RMF': '#f0fdfa',
  'ISO/IEC 42001': '#faf5ff',
};

const PDF_TEXT = '#111827';
const PDF_MUTED = '#6b7280';
const PDF_BORDER = '#e5e7eb';
const PDF_REMEDIATION_BG = '#ecfdf5';

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

function drawHeader(doc: PDFDoc, total: number, generatedAt: string) {
  doc.font('Helvetica-Bold').fontSize(20).fillColor(PDF_TEXT)
    .text('InfraRails — Compliance Report');
  doc.moveDown(0.2);
  doc.font('Helvetica').fontSize(10).fillColor(PDF_MUTED)
    .text('EU AI Act Article 12  ·  NIST AI RMF  ·  ISO/IEC 42001');
  doc.fontSize(9).fillColor(PDF_MUTED)
    .text(`${generatedAt}  ·  ${total} findings`);
  doc.moveDown(0.8);
}

function drawSummaryBar(doc: PDFDoc, s: ScanSummary) {
  const x = doc.page.margins.left;
  const y = doc.y;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const h = 52;

  doc.roundedRect(x, y, w, h, 6).fillAndStroke('#f8fafc', PDF_BORDER);

  const stats: { count: number; label: string; color: string }[] = [
    { count: s.fail, label: 'failed', color: PDF_STATUS_COLORS.FAIL },
    { count: s.warn, label: 'warnings', color: PDF_STATUS_COLORS.WARN },
    { count: s.inconclusive, label: 'inconclusive', color: PDF_STATUS_COLORS.INCONCLUSIVE },
    { count: s.pass, label: 'passed', color: PDF_STATUS_COLORS.PASS },
    { count: s.skip, label: 'skipped', color: PDF_STATUS_COLORS.SKIP },
  ];
  const cellW = w / stats.length;
  stats.forEach((st, i) => {
    const cx = x + i * cellW;
    doc.font('Helvetica-Bold').fontSize(18).fillColor(st.color)
      .text(String(st.count), cx, y + 8, { width: cellW, align: 'center', lineBreak: false });
    doc.font('Helvetica').fontSize(9).fillColor(PDF_MUTED)
      .text(st.label, cx, y + 32, { width: cellW, align: 'center', lineBreak: false });
  });

  doc.y = y + h + 12;
  doc.x = doc.page.margins.left;
}

function drawSectionHeader(doc: PDFDoc, status: FindingStatus, count: number) {
  ensureRoom(doc, 40);
  const x = doc.page.margins.left;
  const y = doc.y;
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const h = 26;
  const padX = 12;
  const gap = 14;

  doc.roundedRect(x, y, w, h, 4).fill(PDF_STATUS_COLORS[status]);

  // Status word - measure width so we can place the label dynamically.
  // "INCONCLUSIVE" at Helvetica-Bold 10pt is wider than the old hardcoded 60pt
  // gap, which caused it to overprint the label text.
  doc.font('Helvetica-Bold').fontSize(10).fillColor('#ffffff');
  const statusW = doc.widthOfString(status);
  doc.text(status, x + padX, y + 8, { lineBreak: false });

  doc.font('Helvetica').fontSize(10).fillColor('#ffffff')
    .text(STATUS_LABELS[status], x + padX + statusW + gap, y + 8, {
      lineBreak: false,
    });

  doc.font('Helvetica-Bold').fontSize(10).fillColor('#ffffff')
    .text(String(count), x, y + 8, { width: w - padX, align: 'right', lineBreak: false });

  doc.y = y + h + 10;
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
  // Rule ID (mono) - right of the pill on the same row
  doc.font('Courier-Bold').fontSize(9).fillColor(PDF_TEXT)
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
    'A passing result indicates that the scanned Terraform configuration satisfies the specific ' +
    'infrastructure-layer prerequisite checked - it does not constitute compliance with any of these ' +
    'frameworks, nor does it substitute for a formal audit, certification, or conformity assessment ' +
    'conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 ' +
    'requires organisational, procedural, and governance measures that are outside the scope of ' +
    'infrastructure scanning. This report should be treated as a pre-audit readiness input, not an ' +
    'attestation of conformance.';

  doc.moveDown(0.5);
  const y = doc.y;
  doc.font('Helvetica').fontSize(8).fillColor(PDF_MUTED);
  const h = doc.heightOfString(text, { width: w - 16 }) + 28;
  doc.roundedRect(x, y, w, h, 4).fillAndStroke('#f8fafc', PDF_BORDER);
  doc.font('Helvetica-Bold').fontSize(9).fillColor(PDF_TEXT)
    .text('Disclaimer', x + 8, y + 8, { lineBreak: false });
  doc.font('Helvetica').fontSize(8).fillColor(PDF_MUTED)
    .text(text, x + 8, y + 22, { width: w - 16 });
  doc.y = y + h;
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
      Title: 'InfraRails — Compliance Report',
      Producer: 'infrarails',
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
