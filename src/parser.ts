import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ParsedFile, HCL2JSONOutput } from './types';
import { parseCfnTemplate, rawTextSniffsCfn } from './cfn/template';
import { normaliseCfnTemplate } from './cfn/normalise';

const SKIP_DIRS = new Set([
  'node_modules',         // JS/TS dependencies (CDK for Terraform)
  'venv', 'env',          // Python virtualenvs (.venv is caught by the leading-dot check)
  '__pycache__',          // Python bytecode cache
  'examples',             // demo configs in shared module repos - not production infra
  'test', 'tests',        // Terraform test fixtures intentionally omit compliance controls
  'testdata', 'fixtures', // Sibling-tool fixtures (e.g. pike/src/testdata) - not the user's infra
  'vendor',               // vendored module copies
]);

/**
 * Recursively collect Terraform config files (.tf and .tf.json) from a directory.
 *
 * Terraform supports two on-disk syntaxes for the same configuration: HCL (.tf)
 * and JSON (.tf.json). cdktf, terragrunt, and various code generators emit the
 * JSON form, so a scanner that ignored .tf.json would be blind to those repos.
 */
export function collectTfFiles(dir: string): string[] {
  return collectFiles(dir, (name) => name.endsWith('.tf') || name.endsWith('.tf.json'));
}

/**
 * Recursively collect CloudFormation template *candidates*: .yaml/.yml plus
 * .json that is not Terraform JSON. Whether a candidate actually IS a CFN
 * template is decided by content (looksLikeCfnTemplate) in parseAllIaCFiles -
 * a Kubernetes manifest or a package.json walks past this filter and is then
 * skipped on shape.
 */
export function collectCfnCandidates(dir: string): string[] {
  return collectFiles(
    dir,
    (name) =>
      name.endsWith('.yaml') ||
      name.endsWith('.yml') ||
      (name.endsWith('.json') && !name.endsWith('.tf.json')),
  );
}

function collectFiles(dir: string, matches: (fileName: string) => boolean): string[] {
  const results: string[] = [];

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile() && matches(entry.name)) {
        results.push(fullPath);
      }
    }
  }

  walk(dir);
  return results.sort();
}

/**
 * Parse a single Terraform config file. .tf is converted via hcl2json;
 * .tf.json is parsed as JSON directly. Both yield the same HCL2JSONOutput shape.
 */
export function parseTfFile(filePath: string): ParsedFile {
  const rawHcl = fs.readFileSync(filePath, 'utf-8');

  let json: HCL2JSONOutput;
  if (filePath.endsWith('.tf.json')) {
    json = JSON.parse(rawHcl);
  } else {
    // Pipe HCL to hcl2json over stdin via spawnSync. We deliberately do NOT
    // use a shell here: the previous bash here-string (`hcl2json <<< '...'`)
    // tied us to /bin/bash and required fragile single-quote escaping. spawn
    // with no shell is portable across macOS, Linux, and native Windows
    // (Node resolves `hcl2json.exe` automatically on win32).
    const result = spawnSync('hcl2json', [], {
      input: rawHcl,
      encoding: 'utf-8',
    });
    if (result.error) {
      throw new Error(
        `Failed to invoke hcl2json for ${filePath}: ${result.error.message}`,
      );
    }
    if (result.status !== 0) {
      const stderr = (result.stderr || '').trim();
      throw new Error(
        `hcl2json exited with status ${result.status} on ${filePath}` +
          (stderr ? `: ${stderr}` : ''),
      );
    }
    json = JSON.parse(result.stdout);
  }

  return { filePath, json, rawHcl };
}

/**
 * Parse all .tf and .tf.json files from a directory.
 */
export function parseAllTfFiles(dir: string): ParsedFile[] {
  const tfFiles = collectTfFiles(dir);
  return tfFiles.map((f) => parseTfFile(f));
}

export type IacInputMode = 'auto' | 'tf' | 'cfn';

/**
 * Parse every supported IaC file in a directory into the shared ParsedFile
 * shape: Terraform natively, CloudFormation via the CFN normaliser. Mixed
 * directories Just Work - each file is routed by extension + content shape,
 * so a repo holding a Terraform module next to a SAM template scans both.
 *
 * `mode` forces one dialect for CI pipelines that want a hard guarantee:
 * 'tf' silently skips CFN templates, 'cfn' skips Terraform.
 *
 * Error policy for CFN candidates that fail to parse: fatal only when the
 * raw text plausibly IS a CFN template (rawTextSniffsCfn) - a malformed
 * template must not be silently ignored by a compliance scanner. Unrelated
 * YAML that the parser chokes on (a helm chart with {{ }} templating) is
 * skipped.
 */
export function parseAllIaCFiles(dir: string, mode: IacInputMode = 'auto'): ParsedFile[] {
  const results: ParsedFile[] = [];

  if (mode !== 'cfn') {
    results.push(...parseAllTfFiles(dir));
  }

  if (mode !== 'tf') {
    for (const filePath of collectCfnCandidates(dir)) {
      const raw = fs.readFileSync(filePath, 'utf-8');
      let template;
      try {
        template = parseCfnTemplate(filePath, raw);
      } catch (err) {
        if (rawTextSniffsCfn(raw)) {
          throw new Error(
            `CloudFormation template ${filePath} could not be parsed: ` +
              `${err instanceof Error ? err.message : String(err)}`,
          );
        }
        continue; // unparseable non-CFN YAML/JSON (helm chart, etc.)
      }
      if (!template) continue; // parsed fine but not a CFN template
      results.push(normaliseCfnTemplate(template));
    }
  }

  return results;
}
