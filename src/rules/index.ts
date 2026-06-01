import { ScanRule } from '../types';
import { bedrockLoggingRule } from './bedrock-logging';
import { cwRetentionRule } from './cw-retention';
import { s3LifecycleRule } from './s3-lifecycle';
import { s3VersioningRule } from './s3-versioning';
import { s3EncryptionRule } from './s3-encryption';
import { cloudtrailRule } from './cloudtrail';
import { remoteModuleWallRule } from './module-wall';
import { agentGuardrailRule } from './agent-guardrail';
import { guardrailPresenceRule } from './guardrail-presence';
import { hardRailsRule } from './hard-rails';
import { planDeletionsRule } from './plan-deletions';

export const allRules: ScanRule[] = [
  bedrockLoggingRule,
  cwRetentionRule,
  s3LifecycleRule,
  s3VersioningRule,
  s3EncryptionRule,
  cloudtrailRule,
  remoteModuleWallRule,
  agentGuardrailRule,
  guardrailPresenceRule,
  hardRailsRule,
  planDeletionsRule,
];
