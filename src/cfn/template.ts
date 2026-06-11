import { parseDocument, isMap, isScalar, isSeq, Scalar, YAMLMap, YAMLSeq } from 'yaml';

// ---------------------------------------------------------------------------
// CloudFormation template parsing.
//
// Reads a template (YAML with CFN short tags, or JSON) into a CfnTemplate:
// intrinsic functions are canonicalised to their long form ({ Ref: X },
// { 'Fn::GetAtt': [id, attr] }, ...) regardless of which syntax the author
// used, and each resource keeps the line number of its logical-id key (plus
// the line of each top-level Properties key) so findings can point at real
// template lines.
//
// The YAML path deliberately does NOT register custom tags with the yaml
// library. Unknown tags parse as warnings (never errors), the node keeps its
// `.tag`, and we canonicalise during our own AST walk - one walk produces
// both the JS values and the positional data.
// ---------------------------------------------------------------------------

export interface CfnParsedResource {
  logicalId: string;
  cfnType: string;
  properties: Record<string, unknown>;
  condition?: string;
  line?: number;
  /** Line of each top-level Properties key (BucketEncryption, ...). */
  propertyLines: Record<string, number>;
}

export interface CfnTemplate {
  filePath: string;
  raw: string;
  lineCount: number;
  /** Parameters section, canonicalised: { LogBucketName: { Type, Default } } */
  parameters: Record<string, Record<string, unknown>>;
  mappings: Record<string, unknown>;
  resources: CfnParsedResource[];
}

/**
 * Shape check on an already-parsed template body. A JSON/YAML document is a
 * CFN template when it declares AWSTemplateFormatVersion, or a Transform
 * (SAM), or a Resources map whose every entry has an AWS::/Custom:: Type.
 * A package.json or a Kubernetes manifest fails all three.
 */
export function looksLikeCfnTemplate(parsed: unknown): boolean {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.AWSTemplateFormatVersion === 'string') return true;

  const resources = obj.Resources;
  const resourcesAreCfn =
    resources !== null &&
    typeof resources === 'object' &&
    !Array.isArray(resources) &&
    Object.values(resources as Record<string, unknown>).length > 0 &&
    Object.values(resources as Record<string, unknown>).every(
      (r) =>
        r !== null &&
        typeof r === 'object' &&
        typeof (r as Record<string, unknown>).Type === 'string' &&
        /^(AWS|Custom|Alexa)::/.test((r as Record<string, unknown>).Type as string),
    );
  if (resourcesAreCfn) return true;

  // SAM templates may use Serverless::* types but always carry a Transform.
  if (
    (typeof obj.Transform === 'string' || Array.isArray(obj.Transform)) &&
    resources !== null &&
    typeof resources === 'object'
  ) {
    return true;
  }
  return false;
}

/**
 * Cheap raw-text check used to decide whether a file that FAILED to parse was
 * plausibly meant to be a CFN template (-> surface the parse error) or is some
 * unrelated YAML/JSON (helm chart, k8s manifest, package.json -> skip).
 */
export function rawTextSniffsCfn(text: string): boolean {
  if (/AWSTemplateFormatVersion/.test(text)) return true;
  if (/(^|\n)\s*"?Resources"?\s*:/.test(text) && /["']?Type["']?\s*:\s*["']?(AWS|Custom)::/.test(text)) {
    return true;
  }
  return false;
}

/**
 * Parse a CFN template file body. Returns undefined when the document parses
 * but does not look like a CFN template. Throws on YAML/JSON syntax errors -
 * the caller decides (via rawTextSniffsCfn) whether that is fatal.
 */
export function parseCfnTemplate(filePath: string, raw: string): CfnTemplate | undefined {
  const lineCount = raw.split('\n').length;
  if (raw.trimStart().startsWith('{')) {
    return parseJsonTemplate(filePath, raw, lineCount);
  }
  return parseYamlTemplate(filePath, raw, lineCount);
}

// --- YAML ------------------------------------------------------------------

function parseYamlTemplate(filePath: string, raw: string, lineCount: number): CfnTemplate | undefined {
  const doc = parseDocument(raw);
  if (doc.errors.length > 0) {
    throw new Error(`Failed to parse ${filePath}: ${doc.errors[0].message}`);
  }
  const root = doc.contents;
  if (!isMap(root)) return undefined;

  // Shape check runs on the canonicalised JS form.
  const js = nodeToCanonical(root);
  if (!looksLikeCfnTemplate(js)) return undefined;
  const body = js as Record<string, unknown>;

  const resources: CfnParsedResource[] = [];
  const resourcesNode = getMapValue(root, 'Resources');
  if (isMap(resourcesNode)) {
    for (const pair of resourcesNode.items) {
      if (!isScalar(pair.key)) continue;
      const logicalId = String((pair.key as Scalar).value);
      const resNode = pair.value;
      if (!isMap(resNode)) continue;

      const typeNode = getMapValue(resNode, 'Type');
      const cfnType = isScalar(typeNode) ? String(typeNode.value) : undefined;
      if (!cfnType) continue;

      const conditionNode = getMapValue(resNode, 'Condition');
      const condition = isScalar(conditionNode) ? String(conditionNode.value) : undefined;

      const propsNode = getMapValue(resNode, 'Properties');
      const properties = isMap(propsNode)
        ? (nodeToCanonical(propsNode) as Record<string, unknown>)
        : {};

      const propertyLines: Record<string, number> = {};
      if (isMap(propsNode)) {
        for (const p of propsNode.items) {
          if (isScalar(p.key) && p.key.range) {
            propertyLines[String(p.key.value)] = lineOfOffset(raw, p.key.range[0]);
          }
        }
      }

      resources.push({
        logicalId,
        cfnType,
        properties,
        condition,
        line: pair.key.range ? lineOfOffset(raw, pair.key.range[0]) : undefined,
        propertyLines,
      });
    }
  }

  return {
    filePath,
    raw,
    lineCount,
    parameters: asRecordOfRecords(body.Parameters),
    mappings: asRecord(body.Mappings),
    resources,
  };
}

/**
 * Convert a yaml AST node to plain JS, canonicalising CFN short tags
 * (!Ref, !GetAtt, !Sub, ...) to their long form. Plain scalars keep the
 * type the YAML schema resolved (numbers stay numbers, booleans booleans).
 */
function nodeToCanonical(node: unknown): unknown {
  if (node === null || node === undefined) return node;
  if (isScalar(node)) {
    return applyCfnTag((node as Scalar).tag, (node as Scalar).value);
  }
  if (isSeq(node)) {
    const arr = (node as YAMLSeq).items.map((item) => nodeToCanonical(item));
    return applyCfnTag((node as YAMLSeq).tag, arr);
  }
  if (isMap(node)) {
    const obj: Record<string, unknown> = {};
    for (const pair of (node as YAMLMap).items) {
      const key = isScalar(pair.key) ? String((pair.key as Scalar).value) : String(pair.key);
      obj[key] = nodeToCanonical(pair.value);
    }
    return applyCfnTag((node as YAMLMap).tag, obj);
  }
  return node;
}

function applyCfnTag(tag: string | null | undefined, value: unknown): unknown {
  if (!tag || !tag.startsWith('!') || tag.startsWith('!!')) return value;
  const name = tag.slice(1);
  if (name === 'Ref') return { Ref: value };
  if (name === 'Condition') return { Condition: value };
  if (name === 'GetAtt' && typeof value === 'string') {
    const dot = value.indexOf('.');
    return {
      'Fn::GetAtt': dot === -1 ? [value] : [value.slice(0, dot), value.slice(dot + 1)],
    };
  }
  return { [`Fn::${name}`]: value };
}

function getMapValue(map: YAMLMap, key: string): unknown {
  for (const pair of map.items) {
    if (isScalar(pair.key) && String((pair.key as Scalar).value) === key) return pair.value;
  }
  return undefined;
}

function lineOfOffset(raw: string, offset: number): number {
  let line = 1;
  const end = Math.min(offset, raw.length);
  for (let i = 0; i < end; i++) {
    if (raw[i] === '\n') line++;
  }
  return line;
}

// --- JSON ------------------------------------------------------------------

function parseJsonTemplate(filePath: string, raw: string, lineCount: number): CfnTemplate | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Failed to parse ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!looksLikeCfnTemplate(parsed)) return undefined;
  const body = parsed as Record<string, unknown>;

  const resources: CfnParsedResource[] = [];
  const resourcesObj = asRecord(body.Resources);
  const resourcesSectionAt = raw.indexOf('"Resources"');
  for (const [logicalId, res] of Object.entries(resourcesObj)) {
    if (res === null || typeof res !== 'object') continue;
    const r = res as Record<string, unknown>;
    if (typeof r.Type !== 'string') continue;

    // Approximate line: first occurrence of the quoted logical id after the
    // Resources section header. Good enough for finding attribution.
    let line: number | undefined;
    if (resourcesSectionAt !== -1) {
      const at = raw.indexOf(`"${logicalId}"`, resourcesSectionAt);
      if (at !== -1) line = lineOfOffset(raw, at);
    }

    resources.push({
      logicalId,
      cfnType: r.Type,
      properties: asRecord(r.Properties),
      condition: typeof r.Condition === 'string' ? r.Condition : undefined,
      line,
      propertyLines: {},
    });
  }

  return {
    filePath,
    raw,
    lineCount,
    parameters: asRecordOfRecords(body.Parameters),
    mappings: asRecord(body.Mappings),
    resources,
  };
}

// --- shared ----------------------------------------------------------------

function asRecord(v: unknown): Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return {};
  return v as Record<string, unknown>;
}

function asRecordOfRecords(v: unknown): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [k, entry] of Object.entries(asRecord(v))) {
    out[k] = asRecord(entry);
  }
  return out;
}
