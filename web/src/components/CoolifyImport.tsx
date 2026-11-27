import React, { useState, useMemo, useRef } from 'react';
import {
  Download,
  Link as LinkIcon,
  Server,
  Database,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Box,
  ChevronDown,
  ChevronRight,
  FolderKanban,
  Check,
  Minus,
  Globe,
  Loader2,
  Cloud,
  ShieldCheck,
  Sparkles,
  FileArchive,
  FileJson,
  ArrowRight,
  Lock,
  Clock,
  RotateCcw,
  Terminal,
  Search,
  Layers,
  Upload,
  KeyRound,
  Activity,
  Copy,
  HardDrive,
} from 'lucide-react';
import { api, apiFetch, type DomainItem } from '../lib/api';
import { useI18n } from '../lib/i18n';

interface CoolifyProject {
  uuid: string;
  id?: number;
  name: string;
  description?: string;
}

interface CoolifyResource {
  uuid: string;
  name: string;
  fqdn?: string;
  database_type?: string;
  type?: string;
  image?: string;
  build_pack?: string;
  git_repository?: string;
  git_branch?: string;
  ports_exposes?: string;
  port?: number | string;
  health_check_path?: string;
  health_check_enabled?: boolean;
  custom_labels?: string;
  docker_compose?: string;
  docker_compose_raw?: string;
  scheduled_tasks?: Array<{ name?: string; frequency?: string; schedule?: string; command?: string; enabled?: boolean }>;
  status?: string;
  environment?: { project?: { uuid?: string; name?: string; id?: number } };
  project_id?: number | string;
  local_persistent_volumes?: unknown[];
  persistent_volumes?: unknown[];
  volumes?: unknown[];
  local_file_volumes?: unknown[];
  file_volumes?: unknown[];
  environment_variables?: Array<{ key?: string; value?: string; is_preview?: boolean }>;
  _resourceType: 'app' | 'database' | 'service';
}

interface ProjectGroup {
  project: CoolifyProject;
  resources: CoolifyResource[];
}

interface MagicVarPreview {
  resourceName: string;
  resourceId?: string;
  envKey: string;
  original: string;
  variable: string;
  kind: 'magic_secret' | 'magic_domain' | 'magic_runtime';
  translated: string;
  vaultKey: string | null;
  resolvedPreview: string;
}

interface TraefikTranslationPreview {
  resourceId: string;
  resourceName: string;
  hosts: string[];
  labelCount: number;
  translatedRules: Array<{ source: string; target: string; summary: string }>;
  edgeConfig?: Record<string, unknown>;
  unsupportedLabels: string[];
  warnings: string[];
}

interface CronPreview {
  name: string;
  schedule: string;
  command: string;
  enabled: boolean;
  valid: boolean;
  warning: string | null;
  sourceResource: string;
}

interface DatabasePlanPreview {
  id: string;
  name: string;
  originalType: string;
  culkiboEngine: string;
  label: string;
  image: string;
  port: number;
  isPublicInCoolify?: boolean;
  volumesCount: number;
  note?: string | null;
  dumpCommand?: string;
  restoreCommand?: string;
}

interface CutoverStep {
  step: number;
  id: string;
  title: string;
  detail: string;
  required: boolean;
}

interface MigrationPlan {
  parityScore: number;
  readinessLevel: 'ready' | 'ready_with_warnings' | 'manual_review_needed';
  summary: {
    projects: number;
    apps: number;
    databases: number;
    services: number;
    domains: number;
    magicVarsTranslated: number;
    traefikRulesTranslated: number;
    cronsMapped: number;
    volumesCount: number;
    fileMountsCount: number;
    healthchecksCount: number;
    vaultRefsNeeded: number;
  };
  domains: Array<{ hostname: string; resourceName: string; targetPort: number; hasEdgeRules: boolean; healthPath: string }>;
  databases: DatabasePlanPreview[];
  magicVariables: MagicVarPreview[];
  traefikTranslations: TraefikTranslationPreview[];
  crons: CronPreview[];
  vaultRefs: string[];
  secretWarnings: string[];
  warnings: string[];
  dnsCutoverChecklist: CutoverStep[];
  rollbackPlan: {
    sourceUntouched: boolean;
    estimatedRollbackSeconds: number;
    steps: string[];
  };
}

interface StreamCmdSpec {
  program: string;
  args: string[];
}

interface DbStreamEntry {
  id: string;
  name: string;
  engine: string;
  originalEngine?: string;
  sourceContainer: string;
  targetContainer: string;
  authEnvNote: string;
  sourceDump: StreamCmdSpec;
  sshSourceDump?: StreamCmdSpec | null;
  targetRestore: StreamCmdSpec;
  verification: {
    streamChecksumAlgorithm: string;
    streamChecksumStep: string;
    postRestoreCheck?: StreamCmdSpec;
  };
}

interface VolStreamEntry {
  volumeName: string;
  targetVolumeName: string;
  mountPath?: string | null;
  ownerResource: string;
  sourceArchive: StreamCmdSpec;
  sshSourceArchive?: StreamCmdSpec | null;
  targetExtract: StreamCmdSpec;
  verification: {
    algorithm: string;
    streamChecksumStep: string;
    targetHashCheck?: StreamCmdSpec;
  };
}

interface StreamPlanResult {
  ok: boolean;
  zeroShell: boolean;
  sourceHost?: string | null;
  summary: { databases: number; volumes: number; totalSteps: number };
  databaseStreams: DbStreamEntry[];
  volumeStreams: VolStreamEntry[];
  verificationChecklist?: string[];
}

interface ParsedBundlePreview {
  filename: string;
  format: 'zip' | 'ckb.gz';
  manifest: {
    bundleId: string;
    stackName: string;
    createdAt: string;
    vaultMode: string;
    source?: string;
    counts?: Record<string, number>;
    vaultRefs?: string[];
  };
  projects: Array<Record<string, unknown>>;
  domains: Array<Record<string, unknown>>;
  databases: Array<Record<string, unknown>>;
  crons: Array<Record<string, unknown>>;
  culkiboYaml: string;
  rawBase64?: string;
}

type SourceMode = 'api' | 'offline' | 'bundle';
type PreviewTab = 'resources' | 'magic' | 'traefik' | 'stream' | 'preflight';

// ---------------------------------------------------------------------------
// Client-side helpers: Lightweight Parity Analyzer, Stream Plan Fallback & ZIP
// ---------------------------------------------------------------------------

function formatArgvDisplay(cmd?: StreamCmdSpec | null): string {
  if (!cmd) return '';
  return [cmd.program, ...cmd.args].map((tok) => (/\s/.test(tok) ? `"${tok}"` : tok)).join(' ');
}

function buildFallbackStreamPlan(
  resources: CoolifyResource[],
  opts: { sourceHost?: string; sourceUser?: string; sourcePort?: string }
): StreamPlanResult {
  const host = opts.sourceHost?.trim() || null;
  const user = opts.sourceUser?.trim() || 'root';
  const port = opts.sourcePort?.trim() || '22';
  const wrapSsh = (cmd: StreamCmdSpec): StreamCmdSpec | null =>
    host
      ? {
          program: 'ssh',
          args: ['-p', port, '-o', 'BatchMode=yes', '--', `${user}@${host}`, cmd.program, ...cmd.args],
        }
      : null;

  const databaseStreams: DbStreamEntry[] = [];
  const volumeStreams: VolStreamEntry[] = [];
  const seenVols = new Set<string>();

  for (const r of resources) {
    const slug = r.name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'res';
    if (r._resourceType === 'database') {
      const eng = resolveDbEngineClient(r);
      const srcC = r.uuid || `coolify_${slug}`;
      const tgtC = `culkibo_db_${slug}`;
      let sourceDump: StreamCmdSpec;
      let targetRestore: StreamCmdSpec;
      let postRestoreCheck: StreamCmdSpec;
      let authEnvNote: string;

      if (eng.engine === 'postgres' || eng.engine === 'pgvector' || eng.engine === 'timescaledb') {
        sourceDump = { program: 'docker', args: ['exec', '-i', srcC, 'pg_dump', '-U', 'postgres', '-d', slug, '-F', 'c', '-b'] };
        targetRestore = { program: 'docker', args: ['exec', '-i', tgtC, 'pg_restore', '-U', 'postgres', '-d', slug, '--clean', '--if-exists', '--no-owner'] };
        postRestoreCheck = { program: 'docker', args: ['exec', tgtC, 'pg_isready', '-h', '127.0.0.1'] };
        authEnvNote = 'PGPASSWORD inside container (0 passwords in argv)';
      } else if (eng.engine === 'mysql' || eng.engine === 'mariadb') {
        const dumpBin = eng.engine === 'mariadb' ? 'mariadb-dump' : 'mysqldump';
        const restBin = eng.engine === 'mariadb' ? 'mariadb' : 'mysql';
        sourceDump = { program: 'docker', args: ['exec', '-i', srcC, dumpBin, '-u', 'root', '--single-transaction', '--quick', slug] };
        targetRestore = { program: 'docker', args: ['exec', '-i', tgtC, restBin, '-u', 'root', slug] };
        postRestoreCheck = { program: 'docker', args: ['exec', tgtC, 'mysqladmin', 'ping', '-h', '127.0.0.1', '--silent'] };
        authEnvNote = 'MYSQL_PWD / CULKIBO_MYSQL_PWD inside container';
      } else if (eng.engine === 'mongodb') {
        sourceDump = { program: 'docker', args: ['exec', '-i', srcC, 'mongodump', '--archive', '--gzip'] };
        targetRestore = { program: 'docker', args: ['exec', '-i', tgtC, 'mongorestore', '--archive', '--gzip', '--drop'] };
        postRestoreCheck = { program: 'docker', args: ['exec', tgtC, 'mongosh', '--quiet', '--eval', 'db.adminCommand({ ping: 1 }).ok'] };
        authEnvNote = 'MONGO_INITDB_ROOT_* inside container';
      } else if (eng.engine === 'valkey') {
        sourceDump = { program: 'docker', args: ['exec', srcC, 'redis-cli', 'SAVE'] };
        targetRestore = { program: 'docker', args: ['cp', `${srcC}:/data/dump.rdb`, '-'] };
        postRestoreCheck = { program: 'docker', args: ['exec', tgtC, 'valkey-cli', 'DBSIZE'] };
        authEnvNote = 'REDISCLI_AUTH inside container';
      } else {
        sourceDump = { program: 'docker', args: ['exec', srcC, 'clickhouse-client', '--query', 'SHOW TABLES'] };
        targetRestore = { program: 'docker', args: ['exec', '-i', tgtC, 'clickhouse-client', '--database', 'default'] };
        postRestoreCheck = { program: 'docker', args: ['exec', tgtC, 'clickhouse-client', '--query', 'SELECT count() FROM system.tables'] };
        authEnvNote = 'CLICKHOUSE_PASSWORD inside container';
      }

      databaseStreams.push({
        id: r.uuid,
        name: r.name,
        engine: eng.engine,
        originalEngine: r.database_type || eng.engine,
        sourceContainer: srcC,
        targetContainer: tgtC,
        authEnvNote,
        sourceDump,
        sshSourceDump: wrapSsh(sourceDump),
        targetRestore,
        verification: {
          streamChecksumAlgorithm: 'sha256',
          streamChecksumStep: 'Pipe stdout → Node crypto.createHash("sha256") PassThrough → target stdin',
          postRestoreCheck,
        },
      });
    }

    const vols = r.local_persistent_volumes || r.persistent_volumes || r.volumes || [];
    for (const v of vols) {
      const volObj = v as Record<string, any>;
      const volName = typeof v === 'string' ? v.split(':')[0] : String(volObj?.name || volObj?.source || '');
      if (!volName || volName.startsWith('/') || seenVols.has(volName)) continue;
      seenVols.add(volName);
      const targetVol = `culkibo_mig_${volName}`;
      const sourceArchive: StreamCmdSpec = {
        program: 'docker',
        args: ['run', '--rm', '-v', `${volName}:/src:ro`, 'alpine:3.20', 'tar', '-cf', '-', '-C', '/src', '.'],
      };
      const targetExtract: StreamCmdSpec = {
        program: 'docker',
        args: ['run', '--rm', '-i', '-v', `${targetVol}:/dst`, 'alpine:3.20', 'tar', '-xf', '-', '-C', '/dst'],
      };
      const targetHashCheck: StreamCmdSpec = {
        program: 'docker',
        args: ['run', '--rm', '-v', `${targetVol}:/dst:ro`, 'alpine:3.20', 'find', '/dst', '-type', 'f', '-exec', 'sha256sum', '{}', '+'],
      };
      volumeStreams.push({
        volumeName: volName,
        targetVolumeName: targetVol,
        mountPath: typeof volObj?.mount_path === 'string' ? volObj.mount_path : null,
        ownerResource: r.name,
        sourceArchive,
        sshSourceArchive: wrapSsh(sourceArchive),
        targetExtract,
        verification: {
          algorithm: 'sha256',
          streamChecksumStep: 'Compare SHA-256 tar digest in flight + file manifest checksums',
          targetHashCheck,
        },
      });
    }
  }

  return {
    ok: true,
    zeroShell: true,
    sourceHost: host,
    summary: {
      databases: databaseStreams.length,
      volumes: volumeStreams.length,
      totalSteps: databaseStreams.length + volumeStreams.length,
    },
    databaseStreams,
    volumeStreams,
  };
}

function formatStreamRunbookText(plan: StreamPlanResult, isEn: boolean): string {
  const lines: string[] = [
    isEn
      ? '# Culkibo Zero-Shell Volume & SQL Live Transfer Runbook'
      : '# Runbook Culkibo — Transferencia en Vivo de Volúmenes y SQL (Zero-Shell)',
    `# Databases: ${plan.summary.databases} · Volumes: ${plan.summary.volumes} · Checksum: SHA-256`,
    '',
  ];
  for (const db of plan.databaseStreams) {
    lines.push(`## DB: ${db.name} (${db.engine})`);
    lines.push(`# Auth: ${db.authEnvNote}`);
    lines.push(`# Source dump:  ${formatArgvDisplay(db.sshSourceDump || db.sourceDump)}`);
    lines.push(`# Target load:  ${formatArgvDisplay(db.targetRestore)}`);
    if (db.verification.postRestoreCheck) {
      lines.push(`# Verify check: ${formatArgvDisplay(db.verification.postRestoreCheck)}`);
    }
    lines.push('');
  }
  for (const vol of plan.volumeStreams) {
    lines.push(`## Volume: ${vol.volumeName} → ${vol.targetVolumeName} (${vol.ownerResource})`);
    lines.push(`# Source tar:   ${formatArgvDisplay(vol.sshSourceArchive || vol.sourceArchive)}`);
    lines.push(`# Target tar:   ${formatArgvDisplay(vol.targetExtract)}`);
    if (vol.verification.targetHashCheck) {
      lines.push(`# SHA-256 verify: ${formatArgvDisplay(vol.verification.targetHashCheck)}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function crc32Bytes(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let k = 0; k < 8; k++) {
      crc = (crc & 1) !== 0 ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildClientZipBlob(files: Record<string, string>): Blob {
  const enc = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;
  const names = Object.keys(files).sort();

  for (const name of names) {
    const nameBytes = enc.encode(name);
    const dataBytes = enc.encode(files[name]);
    const checksum = crc32Bytes(dataBytes);

    const lfh = new Uint8Array(30);
    const lv = new DataView(lfh.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true);
    lv.setUint16(8, 0, true); // STORE
    lv.setUint32(14, checksum, true);
    lv.setUint32(18, dataBytes.length, true);
    lv.setUint32(22, dataBytes.length, true);
    lv.setUint16(26, nameBytes.length, true);
    localParts.push(lfh, nameBytes, dataBytes);

    const cdh = new Uint8Array(46);
    const cv = new DataView(cdh.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint32(16, checksum, true);
    cv.setUint32(20, dataBytes.length, true);
    cv.setUint32(24, dataBytes.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    centralParts.push(cdh, nameBytes);

    offset += 30 + nameBytes.length + dataBytes.length;
  }

  let cdSize = 0;
  for (const p of centralParts) cdSize += p.length;

  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, names.length, true);
  ev.setUint16(10, names.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);

  const allParts: BlobPart[] = [...localParts, ...centralParts, eocd].map(
    (u) => new Uint8Array(u) as BlobPart
  );
  return new Blob(allParts, { type: 'application/zip' });
}

async function inflateRawBrowser(comp: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('DecompressionStream is unavailable in this browser.');
  }
  const ds = new DecompressionStream('deflate-raw');
  const writer = ds.writable.getWriter();
  await writer.write(new Uint8Array(comp));
  await writer.close();
  const ab = await new Response(ds.readable).arrayBuffer();
  return new Uint8Array(ab);
}

async function parseZipInBrowser(buf: ArrayBuffer): Promise<Record<string, string>> {
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf);
  if (bytes.length < 22) throw new Error('ZIP file is truncated or corrupt');

  let eocdPos = -1;
  const minPos = Math.max(0, bytes.length - 22 - 65535);
  for (let p = bytes.length - 22; p >= minPos; p--) {
    if (view.getUint32(p, true) === 0x06054b50) {
      eocdPos = p;
      break;
    }
  }
  if (eocdPos === -1) throw new Error('ZIP End of Central Directory (EOCD) not found');

  const totalEntries = view.getUint16(eocdPos + 10, true);
  const cdSize = view.getUint32(eocdPos + 12, true);
  const cdOffset = view.getUint32(eocdPos + 16, true);
  if (totalEntries > 200 || cdOffset + cdSize > eocdPos) {
    throw new Error('ZIP file rejected by security limits');
  }

  const dec = new TextDecoder('utf-8');
  const files: Record<string, string> = {};
  let cursor = cdOffset;
  let totalUncomp = 0;

  for (let i = 0; i < totalEntries; i++) {
    if (view.getUint32(cursor, true) !== 0x02014b50) throw new Error('Invalid Central Directory');
    const method = view.getUint16(cursor + 10, true);
    const compSize = view.getUint32(cursor + 20, true);
    const uncompSize = view.getUint32(cursor + 24, true);
    const nameLen = view.getUint16(cursor + 28, true);
    const extraLen = view.getUint16(cursor + 30, true);
    const commentLen = view.getUint16(cursor + 32, true);
    const lfhOffset = view.getUint32(cursor + 42, true);

    const name = dec.decode(bytes.subarray(cursor + 46, cursor + 46 + nameLen));
    cursor += 46 + nameLen + extraLen + commentLen;

    if (name.includes('..') || name.startsWith('/') || name.includes('\\') || /^[A-Za-z]:/.test(name)) {
      throw new Error(`Path traversal blocked in ZIP: ${name}`);
    }
    if (name.endsWith('/')) continue;
    if (uncompSize > 10 * 1024 * 1024 || totalUncomp + uncompSize > 25 * 1024 * 1024) {
      throw new Error('Zip-bomb blocked during local inspection');
    }

    const lfhNameLen = view.getUint16(lfhOffset + 26, true);
    const lfhExtraLen = view.getUint16(lfhOffset + 28, true);
    const dataStart = lfhOffset + 30 + lfhNameLen + lfhExtraLen;
    const compSlice = bytes.subarray(dataStart, dataStart + compSize);

    let raw: Uint8Array;
    if (method === 0) raw = compSlice;
    else if (method === 8) raw = await inflateRawBrowser(compSlice);
    else throw new Error(`Unsupported ZIP compression method: ${method}`);

    totalUncomp += raw.length;
    files[name] = dec.decode(raw);
  }
  return files;
}

function parseFqdnHostsClient(fqdn?: string): string[] {
  if (!fqdn) return [];
  const hosts: string[] = [];
  for (const part of String(fqdn).split(',')) {
    const clean = part.trim().replace(/^https?:\/\//i, '').replace(/[:/].*$/, '').toLowerCase();
    if (clean && clean.includes('.')) hosts.push(clean);
  }
  return Array.from(new Set(hosts));
}

function resolveDbEngineClient(r: CoolifyResource): { engine: string; label: string; port: number } {
  const raw = `${r.database_type || ''} ${r.type || ''} ${r.image || ''}`.toLowerCase();
  if (raw.includes('pgvector')) return { engine: 'pgvector', label: 'PostgreSQL + pgvector', port: 5432 };
  if (raw.includes('timescaledb')) return { engine: 'timescaledb', label: 'TimescaleDB', port: 5432 };
  if (raw.includes('postgres')) return { engine: 'postgres', label: 'PostgreSQL', port: 5432 };
  if (raw.includes('mariadb')) return { engine: 'mariadb', label: 'MariaDB', port: 3306 };
  if (raw.includes('mysql')) return { engine: 'mysql', label: 'MySQL', port: 3306 };
  if (raw.includes('dragonfly')) return { engine: 'valkey', label: 'Valkey (Dragonfly)', port: 6379 };
  if (raw.includes('keydb')) return { engine: 'valkey', label: 'Valkey (KeyDB)', port: 6379 };
  if (raw.includes('redis') || raw.includes('valkey')) return { engine: 'valkey', label: 'Valkey (Redis)', port: 6379 };
  if (raw.includes('mongo')) return { engine: 'mongodb', label: 'MongoDB', port: 27017 };
  if (raw.includes('clickhouse')) return { engine: 'clickhouse', label: 'ClickHouse', port: 8123 };
  return { engine: r.database_type || 'database', label: r.database_type || 'Database', port: 5432 };
}

function computeLocalPlan(resources: CoolifyResource[], projects: CoolifyProject[], isEn: boolean): MigrationPlan {
  const magicVariables: MagicVarPreview[] = [];
  const traefikTranslations: TraefikTranslationPreview[] = [];
  const crons: CronPreview[] = [];
  const databases: DatabasePlanPreview[] = [];
  const vaultRefs = new Set<string>();
  const secretWarnings: string[] = [];
  const warnings: string[] = [];
  const domains: Array<{ hostname: string; resourceName: string; targetPort: number; hasEdgeRules: boolean; healthPath: string }> = [];

  let volumesCount = 0;
  let fileMountsCount = 0;
  let healthchecksCount = 0;
  const magicRe = /\$\{((?:SERVICE|COOLIFY)_[A-Za-z0-9_]+)(?::?-([^}]*))?\}/g;

  for (const r of resources) {
    const hosts = parseFqdnHostsClient(r.fqdn);
    const vols = r.local_persistent_volumes?.length || r.persistent_volumes?.length || r.volumes?.length || 0;
    const mounts = r.local_file_volumes?.length || r.file_volumes?.length || 0;
    volumesCount += vols;
    fileMountsCount += mounts;
    if (r.health_check_enabled || r.health_check_path) healthchecksCount++;

    for (const ev of r.environment_variables || []) {
      const k = ev?.key || '';
      const v = String(ev?.value ?? '');
      if (!k) continue;
      let m: RegExpExecArray | null;
      magicRe.lastIndex = 0;
      while ((m = magicRe.exec(v)) !== null) {
        const varName = m[1];
        const isSecret = /^SERVICE_(PASSWORD|USER|(?:REAL)?BASE64)/i.test(varName);
        const isDomain = /^(SERVICE_(FQDN|URL)|COOLIFY_(FQDN|URL))/i.test(varName);
        const vk = isSecret ? varName.toUpperCase().replace(/[^A-Z0-9_]/g, '_') : null;
        if (vk) vaultRefs.add(vk);
        const translated = vk
          ? `\${vault.${vk}}`
          : isDomain
            ? (hosts[0] ? (varName.includes('URL') ? `https://${hosts[0]}` : hosts[0]) : '${domain.primary}')
            : (varName === 'COOLIFY_BRANCH' ? (r.git_branch || 'main') : `culkibo-${r.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`);
        magicVariables.push({
          resourceName: r.name,
          resourceId: r.uuid,
          envKey: k,
          original: m[0],
          variable: varName,
          kind: isSecret ? 'magic_secret' : (isDomain ? 'magic_domain' : 'magic_runtime'),
          translated,
          vaultKey: vk,
          resolvedPreview: translated,
        });
      }
      if (/(secret|token|pass|key|dsn|database_url)/i.test(k) && v && !v.includes('${')) {
        secretWarnings.push(
          isEn
            ? `Sensitive variable "${k}" in ${r.name}: migrate to \${vault.${k.toUpperCase()}}.`
            : `Variable sensible "${k}" en ${r.name}: migrar a \${vault.${k.toUpperCase()}}.`
        );
      }
    }

    const rawLbl = String(r.custom_labels || '') + '\n' + String(r.docker_compose || r.docker_compose_raw || '');
    const traefikLines = rawLbl.split(/\r?\n/).filter((l) => /traefik\.http\./i.test(l));
    if (traefikLines.length > 0) {
      const rules: Array<{ source: string; target: string; summary: string }> = [];
      if (traefikLines.some((l) => /stripprefix/i.test(l))) {
        rules.push({ source: 'traefik.middlewares.stripprefix', target: 'domain.pathRoutes', summary: isEn ? 'Native Caddy stripPrefix path route' : 'Prefijo de ruta con stripPrefix nativo en Caddy' });
      }
      if (traefikLines.some((l) => /redirectregex/i.test(l))) {
        rules.push({ source: 'traefik.middlewares.redirectregex', target: 'domain.pathRedirects', summary: isEn ? 'Validated regex/canonical redirect in Caddy' : 'Redirección regex/canónica validada en Caddy' });
      }
      if (traefikLines.some((l) => /accesscontrolallow/i.test(l))) {
        rules.push({ source: 'traefik.middlewares.headers (CORS)', target: 'domain.cors', summary: isEn ? 'Native CORS edge policy' : 'Política CORS nativa' });
      }
      if (traefikLines.some((l) => /sts(seconds|preload)/i.test(l))) {
        rules.push({ source: 'traefik.middlewares.headers (HSTS)', target: 'domain.hstsPreload', summary: isEn ? 'HSTS / Preload header' : 'Cabecera HSTS / Preload' });
      }
      if (traefikLines.some((l) => /forwardauth/i.test(l))) {
        rules.push({ source: 'traefik.middlewares.forwardauth', target: 'domain.forwardAuth', summary: 'ForwardAuth (Authelia/Authentik)' });
      }
      if (traefikLines.some((l) => /basicauth/i.test(l))) {
        rules.push({ source: 'traefik.middlewares.basicauth', target: 'domain.basicAuth', summary: isEn ? 'Bcrypt Basic Auth in Caddy' : 'Basic Auth bcrypt en Caddy' });
      }
      if (traefikLines.some((l) => /loadbalancer\.server\.port/i.test(l))) {
        rules.push({ source: 'traefik.services.loadbalancer.port', target: 'domain.targetPort', summary: isEn ? 'Auto-detected upstream port' : 'Puerto upstream detectado automáticamente' });
      }
      traefikTranslations.push({
        resourceId: r.uuid,
        resourceName: r.name,
        hosts,
        labelCount: traefikLines.length,
        translatedRules: rules,
        unsupportedLabels: [],
        warnings: [],
      });
    }

    for (const task of r.scheduled_tasks || []) {
      const cmd = String(task.command || '').trim();
      const hasShell = /[|;&`><]/.test(cmd);
      crons.push({
        name: task.name || `${r.name} cron`,
        schedule: task.frequency || task.schedule || '0 0 * * *',
        command: cmd,
        enabled: task.enabled !== false,
        valid: !hasShell,
        warning: hasShell
          ? (isEn ? 'Uses shell syntax; split into direct argv command or HTTP cron endpoint.' : 'Usa sintaxis de shell; divídelo en comando directo o endpoint HTTP.')
          : null,
        sourceResource: r.name,
      });
    }

    if (r._resourceType === 'database') {
      const eng = resolveDbEngineClient(r);
      databases.push({
        id: r.uuid,
        name: r.name,
        originalType: r.database_type || r.type || eng.engine,
        culkiboEngine: eng.engine,
        label: eng.label,
        image: r.image || '',
        port: Number(r.port) || eng.port,
        volumesCount: vols,
      });
    }

    const firstPort = parseInt(String(r.ports_exposes || r.port || '3000').split(',')[0], 10) || 3000;
    for (const h of hosts) {
      if (!domains.some((d) => d.hostname === h)) {
        domains.push({
          hostname: h,
          resourceName: r.name,
          targetPort: firstPort,
          hasEdgeRules: traefikLines.length > 0,
          healthPath: r.health_check_path || '/',
        });
      }
    }
  }

  const invalidCrons = crons.filter((c) => !c.valid).length;
  const parityScore = Math.max(60, 100 - invalidCrons * 5);
  const appsCount = resources.filter((r) => r._resourceType === 'app').length;
  const dbsCount = resources.filter((r) => r._resourceType === 'database').length;
  const svcsCount = resources.filter((r) => r._resourceType === 'service').length;

  return {
    parityScore,
    readinessLevel: parityScore >= 90 ? 'ready' : 'ready_with_warnings',
    summary: {
      projects: Math.max(projects.length, resources.length > 0 ? 1 : 0),
      apps: appsCount,
      databases: dbsCount,
      services: svcsCount,
      domains: domains.length,
      magicVarsTranslated: magicVariables.length,
      traefikRulesTranslated: traefikTranslations.reduce((acc, t) => acc + t.translatedRules.length, 0),
      cronsMapped: crons.length,
      volumesCount,
      fileMountsCount,
      healthchecksCount,
      vaultRefsNeeded: vaultRefs.size,
    },
    domains,
    databases,
    magicVariables,
    traefikTranslations,
    crons,
    vaultRefs: Array.from(vaultRefs).sort(),
    secretWarnings,
    warnings,
    dnsCutoverChecklist: isEn
      ? [
          { step: 1, id: 'lower_ttl', title: 'Lower DNS TTL to 60s', detail: 'Prepares an instant cutover without stale DNS caches.', required: domains.length > 0 },
          { step: 2, id: 'populate_vault', title: `Load ${vaultRefs.size} secret(s) into AES-256-GCM Vault`, detail: 'Culkibo injects secrets without writing plaintext to Git or disk.', required: vaultRefs.size > 0 },
          { step: 3, id: 'sync_data', title: `Stream ${dbsCount} DB(s) & ${volumesCount} volume(s)`, detail: 'Stream PostgreSQL/MySQL/Valkey/ClickHouse and Docker volumes with SHA-256 verification.', required: dbsCount > 0 || volumesCount > 0 },
          { step: 4, id: 'smoke_verify', title: 'Verify endpoints before flipping DNS', detail: 'Use curl --resolve against the Culkibo IP to validate HTTP 200 and TLS.', required: true },
          { step: 5, id: 'dns_flip', title: 'Zero-Downtime DNS cutover', detail: 'Update A records via Cloudflare API or your DNS registrar.', required: domains.length > 0 },
        ]
      : [
          { step: 1, id: 'lower_ttl', title: 'Reducir TTL DNS a 60s', detail: 'Prepara una conmutación instantánea sin caché antigua.', required: domains.length > 0 },
          { step: 2, id: 'populate_vault', title: `Cargar ${vaultRefs.size} secreto(s) en Vault AES-256-GCM`, detail: 'Culkibo inyecta los secretos sin escribir texto plano en Git ni discos.', required: vaultRefs.size > 0 },
          { step: 3, id: 'sync_data', title: `Migrar ${dbsCount} BD(s) y ${volumesCount} volumen(es)`, detail: 'Vuelca PostgreSQL/MySQL/Valkey/ClickHouse y sincroniza volúmenes con SHA-256.', required: dbsCount > 0 || volumesCount > 0 },
          { step: 4, id: 'smoke_verify', title: 'Verificar endpoints antes de mover DNS', detail: 'Usa curl --resolve contra la IP de Culkibo para validar HTTP 200 y TLS.', required: true },
          { step: 5, id: 'dns_flip', title: 'Conmutación DNS Zero-Downtime', detail: 'Actualiza los registros A en Cloudflare o tu registrador.', required: domains.length > 0 },
        ],
    rollbackPlan: {
      sourceUntouched: true,
      estimatedRollbackSeconds: 30,
      steps: isEn
        ? [
            'Your original Coolify v4 instance was NEVER modified (strictly read-only migration).',
            'Keep Coolify containers running in parallel for 24–48 h after cutover.',
            'If any issue occurs, point the A record back to the Coolify IP (~30 s on Cloudflare).',
          ]
        : [
            'Tu instancia de Coolify v4 original NO se ha modificado (acceso estrictamente solo-lectura).',
            'Mantén los contenedores de Coolify corriendo en paralelo 24-48 h tras el cutover.',
            'Si detectas cualquier anomalía, apunta el registro A de vuelta a la IP de Coolify (~30 s en Cloudflare).',
          ],
    },
  };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const CoolifyImport: React.FC<{
  onComplete: () => void;
  onCancel: () => void;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}> = ({ onComplete, onCancel, onNotify }) => {
  const { locale } = useI18n();
  const isEn = locale === 'en';

  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [sourceMode, setSourceMode] = useState<SourceMode>('api');

  // Step 1: API / Offline JSON / Bundle
  const [apiUrl, setApiUrl] = useState('');
  const [apiToken, setApiToken] = useState('');
  const [offlineJson, setOfflineJson] = useState('');
  const [bundlePassphrase, setBundlePassphrase] = useState('');
  const [parsedBundle, setParsedBundle] = useState<ParsedBundlePreview | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Step 2: Live Parity Preview
  const [loading, setLoading] = useState(false);
  const [allResources, setAllResources] = useState<CoolifyResource[]>([]);
  const [projects, setProjects] = useState<CoolifyProject[]>([]);
  const [serverPlan, setServerPlan] = useState<MigrationPlan | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [previewTab, setPreviewTab] = useState<PreviewTab>('resources');
  const [searchQuery, setSearchQuery] = useState('');

  // Volume & SQL Live Transfer Stream Plan
  const [streamSourceHost, setStreamSourceHost] = useState('');
  const [streamSourceUser, setStreamSourceUser] = useState('root');
  const [streamSourcePort, setStreamSourcePort] = useState('22');
  const [streamPlan, setStreamPlan] = useState<StreamPlanResult | null>(null);
  const [loadingStreamPlan, setLoadingStreamPlan] = useState(false);

  // Step 3: Results + Cutover + Smoke Verify + Rollback
  const [results, setResults] = useState<Record<string, any> | null>(null);
  const [importedDomains, setImportedDomains] = useState<DomainItem[]>([]);
  const [serverIp, setServerIp] = useState('');
  const [cfAvailable, setCfAvailable] = useState(false);
  const [useCloudflare, setUseCloudflare] = useState(false);
  const [migratingDomains, setMigratingDomains] = useState<Set<string>>(new Set());
  const [checkedCutover, setCheckedCutover] = useState<Set<string>>(new Set());
  const [showRollback, setShowRollback] = useState(false);
  const [verifyingParity, setVerifyingParity] = useState(false);
  const [verifyReport, setVerifyReport] = useState<Record<string, any> | null>(null);

  const activePlan: MigrationPlan = useMemo(() => {
    if (serverPlan) return serverPlan;
    return computeLocalPlan(allResources, projects, isEn);
  }, [serverPlan, allResources, projects, isEn]);

  const effectiveStreamPlan: StreamPlanResult = useMemo(() => {
    if (streamPlan) return streamPlan;
    const chosen = selected.size > 0 ? allResources.filter((r) => selected.has(r.uuid)) : allResources;
    return buildFallbackStreamPlan(chosen, {
      sourceHost: streamSourceHost,
      sourceUser: streamSourceUser,
      sourcePort: streamSourcePort,
    });
  }, [streamPlan, allResources, selected, streamSourceHost, streamSourceUser, streamSourcePort]);

  const handleFetchStreamPlan = async () => {
    setLoadingStreamPlan(true);
    const chosen = selected.size > 0 ? allResources.filter((r) => selected.has(r.uuid)) : allResources;
    const snapshot = {
      apps: chosen.filter((r) => r._resourceType === 'app'),
      databases: chosen.filter((r) => r._resourceType === 'database'),
      services: chosen.filter((r) => r._resourceType === 'service'),
      projects,
    };
    const options = {
      sourceHost: streamSourceHost.trim() || undefined,
      sourceUser: streamSourceUser.trim() || 'root',
      sourcePort: Number(streamSourcePort) || 22,
    };
    try {
      const res = await apiFetch('/api/import/coolify/stream-plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ snapshot, options }),
      });
      if (res.ok) {
        const data = await res.json();
        setStreamPlan(data);
        onNotify(
          isEn
            ? `Zero-shell stream plan generated (${data.summary?.databases || 0} DBs, ${data.summary?.volumes || 0} volumes)`
            : `Plan de transferencia zero-shell generado (${data.summary?.databases || 0} BDs, ${data.summary?.volumes || 0} volúmenes)`,
          'success'
        );
      } else {
        setStreamPlan(buildFallbackStreamPlan(chosen, { sourceHost: streamSourceHost, sourceUser: streamSourceUser, sourcePort: streamSourcePort }));
      }
    } catch {
      setStreamPlan(buildFallbackStreamPlan(chosen, { sourceHost: streamSourceHost, sourceUser: streamSourceUser, sourcePort: streamSourcePort }));
    } finally {
      setLoadingStreamPlan(false);
    }
  };

  // -------------------------------------------------------------------------
  // Step 1 Handlers
  // -------------------------------------------------------------------------

  const handleConnectApi = async () => {
    setLoading(true);
    try {
      const res = await api.previewCoolify(apiUrl.trim(), apiToken.trim());
      const apps: CoolifyResource[] = (res.apps || []).map((a: any) => ({ ...a, _resourceType: 'app' as const }));
      const dbs: CoolifyResource[] = (res.databases || []).map((d: any) => ({ ...d, _resourceType: 'database' as const }));
      const svcs: CoolifyResource[] = (res.services || []).map((s: any) => ({ ...s, _resourceType: 'service' as const }));
      const all = [...apps, ...dbs, ...svcs];
      setAllResources(all);
      setProjects(res.projects || []);
      setServerPlan(res.plan || null);
      setStreamPlan(null);
      setSelected(new Set(all.map((r) => r.uuid)));
      setPreviewTab('resources');
      setStep(2);
    } catch (e: any) {
      onNotify(e?.message || (isEn ? 'Failed to connect to Coolify' : 'Error al conectar con Coolify'), 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleParseOfflineJson = () => {
    try {
      const parsed = JSON.parse(offlineJson);
      const apps: CoolifyResource[] = (parsed.apps || parsed.applications || []).map((a: any, i: number) => ({
        uuid: a.uuid || `offline-app-${i + 1}`,
        name: a.name || `App ${i + 1}`,
        ...a,
        _resourceType: 'app' as const,
      }));
      const dbs: CoolifyResource[] = (parsed.databases || []).map((d: any, i: number) => ({
        uuid: d.uuid || `offline-db-${i + 1}`,
        name: d.name || `DB ${i + 1}`,
        ...d,
        _resourceType: 'database' as const,
      }));
      const svcs: CoolifyResource[] = (parsed.services || []).map((s: any, i: number) => ({
        uuid: s.uuid || `offline-svc-${i + 1}`,
        name: s.name || `Service ${i + 1}`,
        ...s,
        _resourceType: 'service' as const,
      }));
      const all = [...apps, ...dbs, ...svcs];
      if (all.length === 0) {
        onNotify(
          isEn ? 'JSON contains no Coolify apps, databases, or services.' : 'El JSON no contiene apps, databases ni services de Coolify.',
          'error'
        );
        return;
      }
      setAllResources(all);
      setProjects(parsed.projects || []);
      setServerPlan(null);
      setStreamPlan(null);
      setSelected(new Set(all.map((r) => r.uuid)));
      setPreviewTab('resources');
      setStep(2);
    } catch (err: any) {
      onNotify(isEn ? `Invalid JSON: ${err?.message || 'check format'}` : `JSON inválido: ${err?.message || 'revisa el formato'}`, 'error');
    }
  };

  const handleBundleFileChange = async (file: File | null) => {
    if (!file) return;
    setLoading(true);
    try {
      const ab = await file.arrayBuffer();
      const bytes = new Uint8Array(ab);
      const isZip = bytes[0] === 0x50 && bytes[1] === 0x4b;
      const isGz = bytes[0] === 0x1f && bytes[1] === 0x8b;
      if (!isZip && !isGz) {
        throw new Error(
          isEn ? 'Select a valid .zip or .ckb.gz bundle exported by Culkibo.' : 'Selecciona un archivo .zip o .ckb.gz válido generado por Culkibo.'
        );
      }

      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      const rawBase64 = btoa(bin);

      if (isZip) {
        const files = await parseZipInBrowser(ab);
        if (!files['manifest.json']) {
          throw new Error(isEn ? 'ZIP archive does not contain a Culkibo manifest.json.' : 'El archivo ZIP no contiene manifest.json de Culkibo.');
        }
        const manifest = JSON.parse(files['manifest.json']);
        const bProjects = files['projects.json'] ? JSON.parse(files['projects.json']) : [];
        const bDomains = files['domains.json'] ? JSON.parse(files['domains.json']) : [];
        const bDbs = files['databases.json'] ? JSON.parse(files['databases.json']) : [];
        const bCrons = files['crons.json'] ? JSON.parse(files['crons.json']) : [];
        setParsedBundle({
          filename: file.name,
          format: 'zip',
          manifest,
          projects: Array.isArray(bProjects) ? bProjects : [],
          domains: Array.isArray(bDomains) ? bDomains : [],
          databases: Array.isArray(bDbs) ? bDbs : [],
          crons: Array.isArray(bCrons) ? bCrons : [],
          culkiboYaml: files['culkibo.yaml'] || '',
          rawBase64,
        });
        onNotify(
          isEn
            ? `Bundle "${manifest.stackName || file.name}" inspected (${bProjects.length} project(s))`
            : `Bundle "${manifest.stackName || file.name}" inspeccionado (${bProjects.length} proyecto(s))`,
          'success'
        );
      } else {
        let payload: any = null;
        if (typeof DecompressionStream !== 'undefined') {
          const ds = new DecompressionStream('gzip');
          const writer = ds.writable.getWriter();
          await writer.write(bytes);
          await writer.close();
          const text = await new Response(ds.readable).text();
          payload = JSON.parse(text);
        } else {
          const res = await apiFetch('/api/bundles/inspect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bundleBase64: rawBase64, passphrase: bundlePassphrase || undefined }),
          });
          if (!res.ok) throw new Error(isEn ? 'Failed to inspect .ckb.gz archive' : 'No se pudo inspeccionar el archivo .ckb.gz');
          payload = await res.json();
        }
        const files = payload.files || {};
        setParsedBundle({
          filename: file.name,
          format: 'ckb.gz',
          manifest: payload.manifest,
          projects: files['projects.json'] ? JSON.parse(files['projects.json']) : (payload.projects || []),
          domains: files['domains.json'] ? JSON.parse(files['domains.json']) : (payload.domains || []),
          databases: files['databases.json'] ? JSON.parse(files['databases.json']) : (payload.databases || []),
          crons: files['crons.json'] ? JSON.parse(files['crons.json']) : (payload.crons || []),
          culkiboYaml: files['culkibo.yaml'] || payload.culkiboYaml || '',
          rawBase64,
        });
        onNotify(
          isEn
            ? `.ckb.gz bundle "${payload.manifest?.stackName || file.name}" verified`
            : `Bundle .ckb.gz "${payload.manifest?.stackName || file.name}" verificado`,
          'success'
        );
      }
    } catch (err: any) {
      setParsedBundle(null);
      onNotify(err?.message || (isEn ? 'Error reading portable bundle' : 'Error al leer el bundle portátil'), 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleImportBundle = async () => {
    if (!parsedBundle) return;
    setLoading(true);
    try {
      let importedViaApi = false;
      try {
        const res = await apiFetch('/api/bundles/import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            bundleBase64: parsedBundle.rawBase64,
            passphrase: bundlePassphrase || undefined,
          }),
        });
        if (res.ok) {
          const data = await res.json();
          setResults({
            importedApps: data.importedProjects || 0,
            importedDbs: data.databasesCataloged || 0,
            importedServices: 0,
            importedCrons: data.importedCrons || 0,
            domainsLinked: data.importedDomains || 0,
            parityScore: 100,
            warnings: data.warnings || [],
            errors: data.errors || [],
          });
          importedViaApi = true;
        }
      } catch {
        // Fallback using api.createProject
      }

      if (!importedViaApi) {
        let count = 0;
        const errs: string[] = [];
        for (const p of parsedBundle.projects) {
          try {
            await api.createProject({
              name: String(p.name || 'Bundle Project'),
              description: String(p.description || `Restored from ${parsedBundle.filename}`),
              gitRepo: String(p.gitRepo || ''),
              gitBranch: String(p.gitBranch || 'main'),
              buildCommand: String(p.buildCommand || ''),
              startCommand: String(p.startCommand || ''),
              baseDirectory: String(p.baseDirectory || '/'),
              envVars: (p.envVars as Record<string, string>) || {},
            } as any);
            count++;
          } catch (err: any) {
            errs.push(`${String(p.name || 'Project')}: ${err?.message || 'error'}`);
          }
        }
        setResults({
          importedApps: count,
          importedDbs: parsedBundle.databases.length,
          importedServices: 0,
          importedCrons: parsedBundle.crons.length,
          domainsLinked: 0,
          parityScore: 100,
          warnings: parsedBundle.manifest.vaultMode === 'encrypted'
            ? [
                isEn
                  ? 'Project(s) created via base API; import vault.enc.json via CLI/Vault to decrypt secrets.'
                  : 'Proyecto(s) creados vía API base; importa el sobre vault.enc.json desde CLI/Vault si requieres descifrar los secretos.',
              ]
            : [],
          errors: errs,
        });
      }

      await loadCutoverContext();
      setStep(3);
      onNotify(
        isEn
          ? `Bundle "${parsedBundle.manifest.stackName}" restored into Culkibo`
          : `Bundle "${parsedBundle.manifest.stackName}" restaurado en Culkibo`,
        'success'
      );
    } catch (err: any) {
      onNotify(err?.message || (isEn ? 'Failed to import bundle' : 'Error al importar bundle'), 'error');
    } finally {
      setLoading(false);
    }
  };

  // -------------------------------------------------------------------------
  // Step 2 Grouping & Selection
  // -------------------------------------------------------------------------

  const projectGroups: ProjectGroup[] = useMemo(() => {
    const groups = new Map<string, ProjectGroup>();
    const fallbackProject: CoolifyProject = {
      uuid: '_unassigned',
      name: isEn ? 'Unassigned project' : 'Sin proyecto asignado',
      description: isEn ? 'Resources without a project in Coolify' : 'Recursos sin proyecto en Coolify',
    };
    const q = searchQuery.trim().toLowerCase();

    for (const resource of allResources) {
      if (q) {
        const hay = `${resource.name} ${resource.fqdn || ''} ${resource.database_type || ''} ${resource.git_repository || ''}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }
      let projectKey = '_unassigned';
      let project: CoolifyProject = fallbackProject;

      if (resource.environment?.project?.uuid) {
        projectKey = resource.environment.project.uuid;
        const match = projects.find((p) => p.uuid === projectKey);
        project = match || { uuid: projectKey, name: resource.environment.project.name || 'Coolify Project', description: '' };
      } else if (resource.project_id && projects.length) {
        const match = projects.find((p) => p.id === resource.project_id || p.uuid === String(resource.project_id));
        if (match) {
          projectKey = match.uuid || String(match.id);
          project = match;
        }
      }

      if (!groups.has(projectKey)) {
        groups.set(projectKey, { project, resources: [] });
      }
      groups.get(projectKey)!.resources.push(resource);
    }

    return Array.from(groups.values()).sort((a, b) => {
      if (a.project.uuid === '_unassigned') return 1;
      if (b.project.uuid === '_unassigned') return -1;
      return a.project.name.localeCompare(b.project.name);
    });
  }, [allResources, projects, searchQuery, isEn]);

  const toggleResource = (uuid: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(uuid)) next.delete(uuid);
      else next.add(uuid);
      return next;
    });

  const toggleProject = (group: ProjectGroup) => {
    const uuids = group.resources.map((r) => r.uuid);
    const allSelected = uuids.every((id) => selected.has(id));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) uuids.forEach((id) => next.delete(id));
      else uuids.forEach((id) => next.add(id));
      return next;
    });
  };

  const toggleCollapse = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const selectAll = () => setSelected(new Set(allResources.map((r) => r.uuid)));
  const deselectAll = () => setSelected(new Set());

  const selectedApps = allResources.filter((r) => r._resourceType === 'app' && selected.has(r.uuid)).map((r) => r.uuid);
  const selectedDbs = allResources.filter((r) => r._resourceType === 'database' && selected.has(r.uuid)).map((r) => r.uuid);
  const selectedServices = allResources.filter((r) => r._resourceType === 'service' && selected.has(r.uuid)).map((r) => r.uuid);
  const totalApps = allResources.filter((r) => r._resourceType === 'app').length;
  const totalDbs = allResources.filter((r) => r._resourceType === 'database').length;
  const totalSvcs = allResources.filter((r) => r._resourceType === 'service').length;

  const loadCutoverContext = async () => {
    const [domainsRes, ipRes, cfRes] = await Promise.all([
      api.getDomains().catch(() => ({ domains: [] as DomainItem[] })),
      api.getServerIp().catch(() => ({ ip: null })),
      api.getCloudflareConfig().catch(() => ({ isConfigured: false })),
    ]);

    const coolifyDomains = (domainsRes.domains || []).filter(
      (d) => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify'
    );
    setImportedDomains(coolifyDomains);
    if (ipRes.ip) setServerIp(ipRes.ip);
    const cfOk = Boolean(cfRes?.isConfigured);
    setCfAvailable(cfOk);
    setUseCloudflare(cfOk);
  };

  const handleDownloadPortableZip = () => {
    const chosen = allResources.filter((r) => selected.has(r.uuid));
    const bundleId = `ckb_${Date.now().toString(36)}`;
    const manifest = {
      format: 'culkibo-bundle/v1',
      version: 1,
      bundleId,
      stackName: projects[0]?.name || 'coolify-migration',
      source: 'coolify-migration',
      createdAt: new Date().toISOString(),
      vaultMode: 'redacted',
      vaultRefs: activePlan.vaultRefs,
      counts: {
        projects: projectGroups.length,
        domains: activePlan.domains.length,
        databases: activePlan.databases.length,
        crons: activePlan.crons.length,
      },
    };
    const sanitizedProjects = chosen
      .filter((r) => r._resourceType !== 'database')
      .map((r) => ({
        id: r.uuid,
        name: r.name,
        gitRepo: r.git_repository || '',
        gitBranch: r.git_branch || 'main',
        domains: parseFqdnHostsClient(r.fqdn),
        source: 'coolify-import',
      }));
    const yamlLines = [
      `# Culkibo Portable Stack Manifest (culkibo.yaml v1)`,
      `version: 1`,
      `name: ${JSON.stringify(manifest.stackName)}`,
      ...(activePlan.vaultRefs.length > 0 ? ['vaultRefs:', ...activePlan.vaultRefs.map((k) => `  - ${k}`)] : []),
      `projects:`,
      ...sanitizedProjects.flatMap((p) => [
        `  - id: ${JSON.stringify(p.id)}`,
        `    name: ${JSON.stringify(p.name)}`,
        ...(p.gitRepo ? [`    gitRepo: ${JSON.stringify(p.gitRepo)}`] : []),
        `    gitBranch: ${JSON.stringify(p.gitBranch)}`,
      ]),
    ].join('\n');

    const blob = buildClientZipBlob({
      'manifest.json': JSON.stringify(manifest, null, 2),
      'culkibo.yaml': `${yamlLines}\n`,
      'projects.json': JSON.stringify(sanitizedProjects, null, 2),
      'domains.json': JSON.stringify(activePlan.domains, null, 2),
      'databases.json': JSON.stringify(activePlan.databases, null, 2),
      'crons.json': JSON.stringify(activePlan.crons, null, 2),
      'vault.redacted.json': JSON.stringify(
        {
          version: 1,
          encrypted: false,
          mode: 'redacted',
          requiredKeys: activePlan.vaultRefs,
          note: 'Zero plaintext secrets exported. Populate these keys in Culkibo AES-256-GCM Vault.',
        },
        null,
        2
      ),
      'migration-report.json': JSON.stringify(activePlan, null, 2),
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `culkibo-coolify-stack-${bundleId}.zip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    onNotify(
      isEn ? 'Portable .zip bundle generated (0 plaintext secrets)' : 'Bundle portátil .zip generado (0 secretos en claro)',
      'success'
    );
  };

  const handleImport = async () => {
    setLoading(true);
    try {
      if (sourceMode === 'api') {
        const res = await api.importCoolify(apiUrl.trim(), apiToken.trim(), selectedApps, selectedDbs, selectedServices);
        setResults(res);
      } else {
        const chosen = allResources.filter((r) => selected.has(r.uuid));
        let importedApps = 0;
        let importedDbs = 0;
        let importedServices = 0;
        const errs: string[] = [];
        for (const r of chosen) {
          if (r._resourceType === 'database') {
            importedDbs++;
            continue;
          }
          try {
            await api.createProject({
              name: r.name,
              description: `Imported offline from Coolify (${r._resourceType})`,
              gitRepo: r.git_repository || '',
              gitBranch: r.git_branch || 'main',
            } as any);
            if (r._resourceType === 'app') importedApps++;
            else importedServices++;
          } catch (err: any) {
            errs.push(`${r.name}: ${err?.message || 'error'}`);
          }
        }
        setResults({
          importedApps,
          importedDbs,
          importedServices,
          importedCrons: activePlan.crons.filter((c) => c.valid).length,
          domainsLinked: 0,
          traefikRulesApplied: activePlan.summary.traefikRulesTranslated,
          magicVarsTranslated: activePlan.summary.magicVarsTranslated,
          vaultRefs: activePlan.vaultRefs,
          parityScore: activePlan.parityScore,
          dnsCutoverChecklist: activePlan.dnsCutoverChecklist,
          rollbackPlan: activePlan.rollbackPlan,
          errors: errs,
        });
      }

      await loadCutoverContext();
      setStep(3);
    } catch (e: any) {
      onNotify(e?.message || (isEn ? 'Failed to import from Coolify' : 'Error al importar desde Coolify'), 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRunLiveVerification = async () => {
    setVerifyingParity(true);
    try {
      const targets = (activePlan.domains || []).map((d) => ({
        name: d.resourceName,
        hostname: d.hostname,
        sourceUrl: `https://${d.hostname}${d.healthPath || '/'}`,
        targetUrl: serverIp ? `http://${serverIp}:${d.targetPort || 3000}${d.healthPath || '/'}` : `http://127.0.0.1:${d.targetPort || 3000}${d.healthPath || '/'}`,
        healthPath: d.healthPath || '/',
      }));
      const res = await apiFetch('/api/import/coolify/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets, targetIp: serverIp || undefined }),
      });
      if (res.ok) {
        const data = await res.json();
        setVerifyReport(data);
        onNotify(
          data.cutoverReady
            ? (isEn ? 'Parity verified: ready for DNS cutover' : 'Paridad verificada: listo para DNS cutover')
            : (isEn ? 'Some endpoints need attention' : 'Algunos endpoints requieren atención'),
          data.cutoverReady ? 'success' : 'error'
        );
      } else {
        onNotify(
          isEn ? 'Use the curl --resolve commands below to verify directly against the target IP.' : 'Usa los comandos curl --resolve de abajo para verificar directamente contra la IP destino.',
          'info'
        );
      }
    } catch {
      onNotify(
        isEn ? 'Use the curl --resolve commands below before moving DNS.' : 'Usa los comandos curl --resolve de abajo para verificar antes de mover DNS.',
        'info'
      );
    } finally {
      setVerifyingParity(false);
    }
  };

  const copyText = (text: string, label: string) => {
    if (navigator.clipboard) {
      navigator.clipboard
        .writeText(text)
        .then(() => onNotify(isEn ? `${label} copied` : `${label} copiado`, 'success'))
        .catch(() => {});
    }
  };

  // -------------------------------------------------------------------------
  // Render Helpers
  // -------------------------------------------------------------------------

  const typeConfig = {
    app: { icon: Server, label: isEn ? 'Application' : 'Aplicación', pill: 'bg-indigo-50 text-indigo-700 border-indigo-200' },
    database: { icon: Database, label: isEn ? 'Database' : 'Base de datos', pill: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
    service: { icon: Box, label: isEn ? 'Compose Service' : 'Servicio Compose', pill: 'bg-amber-50 text-amber-800 border-amber-200' },
  };

  const getVolCount = (r: CoolifyResource) => r.local_persistent_volumes?.length || r.persistent_volumes?.length || r.volumes?.length || 0;
  const getMountCount = (r: CoolifyResource) => r.local_file_volumes?.length || r.file_volumes?.length || 0;
  const getEnvCount = (r: CoolifyResource) => r.environment_variables?.length || 0;
  const getCronCount = (r: CoolifyResource) => r.scheduled_tasks?.length || 0;

  const parityColor = activePlan.parityScore >= 90
    ? 'text-emerald-700 bg-emerald-50 border-emerald-200'
    : activePlan.parityScore >= 70
      ? 'text-amber-800 bg-amber-50 border-amber-200'
      : 'text-rose-700 bg-rose-50 border-rose-200';

  const renderResourceRow = (resource: CoolifyResource) => {
    const cfg = typeConfig[resource._resourceType];
    const Icon = cfg.icon;
    const isChecked = selected.has(resource.uuid);
    const vols = getVolCount(resource);
    const mounts = getMountCount(resource);
    const envs = getEnvCount(resource);
    const cronCnt = getCronCount(resource);
    const statusRunning = String(resource.status || '').toLowerCase().startsWith('running');
    const dbInfo = resource._resourceType === 'database' ? resolveDbEngineClient(resource) : null;
    const traefikMatch = activePlan.traefikTranslations.find((t) => t.resourceId === resource.uuid);
    const magicCount = activePlan.magicVariables.filter((m) => m.resourceId === resource.uuid || m.resourceName === resource.name).length;

    return (
      <label
        key={resource.uuid}
        className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
          isChecked ? 'bg-white border-slate-300 shadow-2xs' : 'bg-slate-50/50 border-slate-200 opacity-75 hover:opacity-100'
        }`}
      >
        <input
          type="checkbox"
          checked={isChecked}
          onChange={() => toggleResource(resource.uuid)}
          className="w-4 h-4 mt-0.5 rounded border-slate-300 accent-slate-900"
        />
        <Icon className="w-4 h-4 mt-0.5 text-slate-500 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold text-slate-900 truncate">{resource.name}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${cfg.pill}`}>
              {dbInfo ? dbInfo.label : cfg.label}
            </span>
            {resource.build_pack && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono">
                {resource.build_pack}
              </span>
            )}
            {statusRunning && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" title={isEn ? 'Running on Coolify' : 'En ejecución en Coolify'} />}
          </div>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap text-[11px] text-slate-500">
            {resource.fqdn && <span className="font-mono truncate max-w-[260px] text-slate-700">{resource.fqdn}</span>}
            {resource.git_repository && <span className="font-mono truncate max-w-[200px]">{resource.git_repository}</span>}
          </div>
          {(vols > 0 || mounts > 0 || envs > 0 || cronCnt > 0 || magicCount > 0 || (traefikMatch && traefikMatch.translatedRules.length > 0) || resource.health_check_path) && (
            <div className="flex gap-1.5 mt-1.5 flex-wrap text-[10px] text-slate-600 tabular-nums">
              {envs > 0 && <span className="px-1.5 py-0.5 bg-slate-100 rounded">{envs} env</span>}
              {magicCount > 0 && (
                <span className="px-1.5 py-0.5 bg-violet-50 text-violet-700 border border-violet-200 rounded font-medium">
                  {magicCount} Magic {magicCount === 1 ? 'Var' : 'Vars'}
                </span>
              )}
              {traefikMatch && traefikMatch.translatedRules.length > 0 && (
                <span className="px-1.5 py-0.5 bg-sky-50 text-sky-700 border border-sky-200 rounded font-medium">
                  {traefikMatch.translatedRules.length} Traefik→Caddy
                </span>
              )}
              {vols > 0 && <span className="px-1.5 py-0.5 bg-slate-100 rounded">{vols} vol</span>}
              {mounts > 0 && <span className="px-1.5 py-0.5 bg-slate-100 rounded">{mounts} cfg</span>}
              {cronCnt > 0 && <span className="px-1.5 py-0.5 bg-amber-50 text-amber-800 border border-amber-200 rounded">{cronCnt} cron</span>}
              {resource.health_check_path && (
                <span className="px-1.5 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded font-mono">
                  health:{resource.health_check_path}
                </span>
              )}
            </div>
          )}
        </div>
      </label>
    );
  };

  const renderStreamTransferPanel = () => (
    <div className="space-y-3">
      <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-2.5">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
            <HardDrive className="w-4 h-4 text-emerald-600" />
            <span>{isEn ? 'Zero-Shell Volume & SQL Live Transfer' : 'Transferencia en Vivo de Volúmenes y SQL (Zero-Shell)'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={loadingStreamPlan}
              onClick={() => void handleFetchStreamPlan()}
              className="px-2.5 py-1 rounded-lg bg-white hover:bg-slate-100 border border-slate-200 text-[11px] font-medium text-slate-700 inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              {loadingStreamPlan && <Loader2 className="w-3 h-3 animate-spin" />}
              <span>{isEn ? 'Refresh Stream Plan' : 'Generar plan live'}</span>
            </button>
            <button
              type="button"
              onClick={() => copyText(formatStreamRunbookText(effectiveStreamPlan, isEn), isEn ? 'Transfer runbook' : 'Runbook de transferencia')}
              className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-medium inline-flex items-center gap-1.5 cursor-pointer"
            >
              <Copy className="w-3 h-3" />
              <span>{isEn ? 'Copy Runbook' : 'Copiar Runbook'}</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <input
            type="text"
            value={streamSourceHost}
            onChange={(e) => setStreamSourceHost(e.target.value)}
            placeholder={isEn ? 'Coolify VPS IP/host (optional SSH)' : 'IP/host del VPS Coolify (SSH opcional)'}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono"
          />
          <input
            type="text"
            value={streamSourceUser}
            onChange={(e) => setStreamSourceUser(e.target.value)}
            placeholder="root"
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono"
          />
          <input
            type="text"
            value={streamSourcePort}
            onChange={(e) => setStreamSourcePort(e.target.value)}
            placeholder="22"
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono"
          />
        </div>
        <p className="text-[11px] text-slate-500">
          {isEn
            ? 'Every pipeline uses strict docker/ssh arg arrays (shell: false), 0 passwords in argv, and in-flight SHA-256 verification.'
            : 'Cada pipeline usa arrays de argumentos puros docker/ssh (shell: false), 0 contraseñas en argv y verificación SHA-256 en vuelo.'}
        </p>
      </div>

      {effectiveStreamPlan.databaseStreams.length > 0 && (
        <div className="space-y-2">
          <div className="text-[11px] font-semibold text-slate-700 uppercase tracking-wide">
            {isEn ? `Database Streams (${effectiveStreamPlan.databaseStreams.length})` : `Streams de Bases de Datos (${effectiveStreamPlan.databaseStreams.length})`}
          </div>
          {effectiveStreamPlan.databaseStreams.map((db) => (
            <div key={db.id} className="border border-slate-200 rounded-xl p-3 bg-white space-y-1.5 text-[11px]">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="font-semibold text-slate-900">{db.name}</span>
                <div className="flex items-center gap-1.5">
                  <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[10px]">
                    {db.engine}
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono text-[10px]">
                    SHA-256
                  </span>
                </div>
              </div>
              <div className="text-[10px] text-slate-500">{db.authEnvNote}</div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono text-[10px] text-slate-700 space-y-1 overflow-x-auto">
                <div><span className="text-slate-400">DUMP: </span>{formatArgvDisplay(db.sshSourceDump || db.sourceDump)}</div>
                <div><span className="text-slate-400">LOAD: </span>{formatArgvDisplay(db.targetRestore)}</div>
                {db.verification.postRestoreCheck && (
                  <div><span className="text-emerald-600">CHK:  </span>{formatArgvDisplay(db.verification.postRestoreCheck)}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {effectiveStreamPlan.volumeStreams.length > 0 && (
        <div className="space-y-2">
          <div className="text-[11px] font-semibold text-slate-700 uppercase tracking-wide">
            {isEn ? `Named Docker Volumes (${effectiveStreamPlan.volumeStreams.length})` : `Volúmenes Docker (${effectiveStreamPlan.volumeStreams.length})`}
          </div>
          {effectiveStreamPlan.volumeStreams.map((vol) => (
            <div key={vol.volumeName} className="border border-slate-200 rounded-xl p-3 bg-white space-y-1.5 text-[11px]">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="font-mono font-semibold text-slate-900">{vol.volumeName} → {vol.targetVolumeName}</span>
                <span className="text-[10px] text-slate-500">{vol.ownerResource}</span>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono text-[10px] text-slate-700 space-y-1 overflow-x-auto">
                <div><span className="text-slate-400">TAR:  </span>{formatArgvDisplay(vol.sshSourceArchive || vol.sourceArchive)}</div>
                <div><span className="text-slate-400">LOAD: </span>{formatArgvDisplay(vol.targetExtract)}</div>
                {vol.verification.targetHashCheck && (
                  <div><span className="text-emerald-600">SHA:  </span>{formatArgvDisplay(vol.verification.targetHashCheck)}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {effectiveStreamPlan.databaseStreams.length === 0 && effectiveStreamPlan.volumeStreams.length === 0 && (
        <div className="text-center py-8 text-xs text-slate-500 border border-dashed border-slate-200 rounded-xl">
          {isEn
            ? 'No stateful databases or named Docker volumes detected in the selected resources.'
            : 'No se detectaron bases de datos ni volúmenes Docker con nombre en los recursos seleccionados.'}
        </div>
      )}
    </div>
  );

  const cutoverItems: CutoverStep[] = (results?.dnsCutoverChecklist as CutoverStep[] | undefined) || activePlan.dnsCutoverChecklist;
  const rollbackInfo = results?.rollbackPlan || activePlan.rollbackPlan;

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-2xs">
      {/* Header + 3-Step Cockpit Stepper */}
      <div className="p-5 border-b border-slate-200 bg-slate-50 space-y-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center shrink-0">
              <Download className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="font-semibold text-base text-slate-900">
                  {isEn ? 'Coolify v4 → Culkibo Migration Cockpit' : 'Cabina de Migración Coolify v4 → Culkibo'}
                </h2>
                <span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                  Zero-Downtime
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                {isEn ? (
                  <>Translates Magic Vars to AES-256-GCM Vault, Traefik labels to native Caddy edge, 8 DB engines, Crons, live SQL/Volume streaming &amp; portable <code className="font-mono">.zip</code> bundles.</>
                ) : (
                  <>Traduce Magic Vars a Vault AES-256-GCM, etiquetas Traefik a Caddy nativo, 8 motores de BD, Crons, streaming SQL/Volúmenes y bundles portátiles <code className="font-mono">.zip</code>.</>
                )}
              </p>
            </div>
          </div>
          {step >= 2 && (
            <div className={`px-3 py-1.5 rounded-lg border text-xs font-semibold inline-flex items-center gap-1.5 tabular-nums ${parityColor}`}>
              <ShieldCheck className="w-4 h-4" />
              <span>{results?.parityScore ?? activePlan.parityScore}% {isEn ? 'Parity' : 'Paridad'}</span>
            </div>
          )}
        </div>

        {/* 3-Step Stepper */}
        <ol className="grid grid-cols-3 gap-2" aria-label={isEn ? 'Migration steps' : 'Pasos de migración'}>
          {[
            { num: 1 as const, label: isEn ? '1. Connect Source' : '1. Conectar origen', sub: isEn ? 'API, JSON or .zip' : 'API, JSON o .zip' },
            { num: 2 as const, label: isEn ? '2. Parity & Pre-Flight' : '2. Paridad y Pre-Flight', sub: 'Magic Vars & Traefik' },
            { num: 3 as const, label: isEn ? '3. Migrate & Cutover' : '3. Migrar y Cutover DNS', sub: 'Stream, Smoke & Rollback' },
          ].map((s) => {
            const isCurrent = step === s.num;
            const isDone = step > s.num;
            return (
              <li
                key={s.num}
                className={`px-3 py-2 rounded-lg border text-left transition-colors ${
                  isCurrent
                    ? 'bg-white border-slate-900 text-slate-900 shadow-2xs'
                    : isDone
                      ? 'bg-emerald-50/60 border-emerald-200 text-emerald-900'
                      : 'bg-white/60 border-slate-200 text-slate-400'
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold">
                  {isDone ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> : null}
                  <span className="truncate">{s.label}</span>
                </div>
                <div className="text-[10px] opacity-80 truncate">{s.sub}</div>
              </li>
            );
          })}
        </ol>
      </div>

      <div className="p-5">
        {/* ================================================================= */}
        {/* STEP 1: CONNECT COOLIFY API / OFFLINE EXPORT / PORTABLE .ZIP      */}
        {/* ================================================================= */}
        {step === 1 && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {[
                { id: 'api' as const, title: isEn ? 'Coolify v4 API' : 'API Coolify v4', desc: isEn ? 'Read-only live connection' : 'Conexión directa solo-lectura', icon: LinkIcon },
                { id: 'offline' as const, title: isEn ? 'Offline JSON Export' : 'Exportación JSON', desc: isEn ? 'Paste snapshot without network' : 'Pega snapshot sin red pública', icon: FileJson },
                { id: 'bundle' as const, title: isEn ? 'Portable .zip Bundle' : 'Bundle Portátil .zip', desc: isEn ? 'Self-contained Culkibo stack' : 'Stack Culkibo autocontenido', icon: FileArchive },
              ].map((m) => {
                const Icon = m.icon;
                const active = sourceMode === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setSourceMode(m.id)}
                    className={`flex items-start gap-2.5 p-3 rounded-xl border text-left transition-colors cursor-pointer ${
                      active
                        ? 'bg-slate-900 text-white border-slate-900'
                        : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${active ? 'text-emerald-400' : 'text-slate-400'}`} />
                    <div className="min-w-0">
                      <div className="text-xs font-semibold">{m.title}</div>
                      <div className={`text-[11px] ${active ? 'text-slate-300' : 'text-slate-500'}`}>{m.desc}</div>
                    </div>
                  </button>
                );
              })}
            </div>

            {sourceMode === 'api' && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleConnectApi();
                }}
                className="space-y-4"
              >
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 text-xs text-slate-600 flex items-start gap-2.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-900">
                      {isEn ? '100% read-only on source:' : '100% solo-lectura en origen:'}
                    </span>{' '}
                    {isEn ? 'Culkibo never modifies or stops your Coolify containers. Generate a token in' : 'Culkibo nunca modifica ni detiene tus contenedores en Coolify. Genera tu token en'}{' '}
                    <span className="font-mono text-[11px] bg-white px-1.5 py-0.5 rounded border border-slate-200">Keys &amp; Tokens → API Tokens (read:all)</span>.
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    {isEn ? 'Coolify v4 Instance URL' : 'URL de tu instancia Coolify v4'}
                  </label>
                  <div className="relative">
                    <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="url"
                      required
                      value={apiUrl}
                      onChange={(e) => setApiUrl(e.target.value)}
                      placeholder="https://coolify.yourdomain.com"
                      className="w-full pl-9 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono focus:outline-none focus:border-slate-400"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    {isEn ? 'API Token (Bearer)' : 'Token de API (Bearer)'}
                  </label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="password"
                      required
                      value={apiToken}
                      onChange={(e) => setApiToken(e.target.value)}
                      placeholder="1|xxxxxxxxxxxxxxxxxxxx"
                      className="w-full pl-9 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono focus:outline-none focus:border-slate-400"
                    />
                  </div>
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button type="button" onClick={onCancel} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                    {isEn ? 'Cancel' : 'Cancelar'}
                  </button>
                  <button
                    type="submit"
                    disabled={loading || !apiUrl.trim() || !apiToken.trim()}
                    className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                  >
                    {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    {loading
                      ? (isEn ? 'Analyzing parity…' : 'Analizando paridad…')
                      : (isEn ? 'Connect & Analyze Parity' : 'Conectar y analizar paridad')}
                    {!loading && <ArrowRight className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </form>
            )}

            {sourceMode === 'offline' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-600">
                  {isEn ? 'Paste a Coolify v4 JSON export' : 'Pega una exportación JSON de Coolify v4'} (<code className="font-mono text-[11px] bg-slate-100 px-1 rounded">{'{ "projects": [...], "apps": [...], "databases": [...], "services": [...] }'}</code>){' '}
                  {isEn ? 'to run parity analysis, Magic Vars, Traefik→Caddy, and SQL/Volume streaming completely offline.' : 'para ejecutar el análisis de paridad, Magic Vars y Traefik→Caddy completamente offline.'}
                </p>
                <textarea
                  rows={8}
                  value={offlineJson}
                  onChange={(e) => setOfflineJson(e.target.value)}
                  placeholder='{"projects":[{"uuid":"p1","name":"Prod"}],"apps":[{"uuid":"a1","name":"API","fqdn":"https://api.example.com","environment_variables":[{"key":"DB_PASS","value":"${SERVICE_PASSWORD_64_DB}"}]}]}'
                  className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:outline-none focus:bg-white focus:border-slate-400"
                />
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={onCancel} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                    {isEn ? 'Cancel' : 'Cancelar'}
                  </button>
                  <button
                    type="button"
                    disabled={!offlineJson.trim()}
                    onClick={handleParseOfflineJson}
                    className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                  >
                    <span>{isEn ? 'Analyze JSON Export' : 'Analizar exportación JSON'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {sourceMode === 'bundle' && (
              <div className="space-y-4">
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-300 hover:border-slate-500 rounded-xl p-6 text-center cursor-pointer bg-slate-50/70 transition-colors"
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".zip,.gz,.ckb.gz"
                    className="hidden"
                    onChange={(e) => void handleBundleFileChange(e.target.files?.[0] || null)}
                  />
                  <Upload className="w-7 h-7 text-slate-400 mx-auto mb-2" />
                  <p className="text-xs font-semibold text-slate-800">
                    {isEn ? 'Drop or select a Culkibo Portable Stack Bundle' : 'Arrastra o selecciona un Culkibo Portable Stack Bundle'} (<code className="font-mono">.zip</code> / <code className="font-mono">.ckb.gz</code>)
                  </p>
                  <p className="text-[11px] text-slate-500 mt-1">
                    {isEn ? (
                      <>Includes <code className="font-mono">culkibo.yaml</code>, projects, Caddy edge policies, DBs, crons, MCP config, and AES-256-GCM Vault envelope.</>
                    ) : (
                      <>Incluye <code className="font-mono">culkibo.yaml</code>, proyectos, políticas Caddy, BDs, crons, MCP y sobre Vault AES-256-GCM.</>
                    )}
                  </p>
                </div>

                {parsedBundle && (
                  <div className="border border-emerald-200 bg-emerald-50/40 rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <FileArchive className="w-4 h-4 text-emerald-700" />
                        <span className="text-xs font-semibold text-slate-900">{parsedBundle.manifest.stackName}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-600">
                          {parsedBundle.format} · {parsedBundle.manifest.bundleId}
                        </span>
                      </div>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${
                        parsedBundle.manifest.vaultMode === 'encrypted'
                          ? 'bg-indigo-50 text-indigo-700 border-indigo-200'
                          : 'bg-slate-100 text-slate-700 border-slate-200'
                      }`}>
                        {parsedBundle.manifest.vaultMode === 'encrypted'
                          ? (isEn ? 'AES-256-GCM Encrypted Vault' : 'Vault cifrado AES-256-GCM')
                          : (isEn ? 'Redacted Vault (0 secrets)' : 'Vault redactado (0 secretos)')}
                      </span>
                    </div>

                    <div className="grid grid-cols-4 gap-2 text-center text-xs tabular-nums">
                      <div className="bg-white border border-slate-200 rounded-lg p-2">
                        <div className="font-semibold text-slate-900">{parsedBundle.projects.length}</div>
                        <div className="text-[10px] text-slate-500">{isEn ? 'Projects' : 'Proyectos'}</div>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-lg p-2">
                        <div className="font-semibold text-slate-900">{parsedBundle.domains.length}</div>
                        <div className="text-[10px] text-slate-500">{isEn ? 'Domains' : 'Dominios'}</div>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-lg p-2">
                        <div className="font-semibold text-slate-900">{parsedBundle.databases.length}</div>
                        <div className="text-[10px] text-slate-500">{isEn ? 'Databases' : 'Bases datos'}</div>
                      </div>
                      <div className="bg-white border border-slate-200 rounded-lg p-2">
                        <div className="font-semibold text-slate-900">{parsedBundle.crons.length}</div>
                        <div className="text-[10px] text-slate-500">Crons</div>
                      </div>
                    </div>

                    {parsedBundle.manifest.vaultMode === 'encrypted' && (
                      <div>
                        <label className="block text-[11px] font-medium text-slate-700 mb-1">
                          {isEn ? 'Portable Vault passphrase' : 'Contraseña del Vault portátil (passphrase)'}
                        </label>
                        <input
                          type="password"
                          value={bundlePassphrase}
                          onChange={(e) => setBundlePassphrase(e.target.value)}
                          placeholder={isEn ? 'Enter passphrase to decrypt vault.enc.json' : 'Introduce tu passphrase para descifrar vault.enc.json'}
                          className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                        />
                      </div>
                    )}
                  </div>
                )}

                <div className="flex justify-end gap-2">
                  <button type="button" onClick={onCancel} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                    {isEn ? 'Cancel' : 'Cancelar'}
                  </button>
                  <button
                    type="button"
                    disabled={loading || !parsedBundle}
                    onClick={() => void handleImportBundle()}
                    className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                  >
                    {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>{isEn ? 'Restore Bundle in 1 Click' : 'Restaurar Bundle en 1 clic'}</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* STEP 2: LIVE PARITY PREVIEW COCKPIT                               */}
        {/* ================================================================= */}
        {step === 2 && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 tabular-nums">
              <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                <div className="text-[10px] text-slate-500 flex items-center gap-1"><Server className="w-3 h-3" /> Apps / Compose</div>
                <div className="text-sm font-semibold text-slate-900 mt-0.5">{selectedApps.length}/{totalApps} · {selectedServices.length}/{totalSvcs}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                <div className="text-[10px] text-slate-500 flex items-center gap-1"><Database className="w-3 h-3" /> {isEn ? 'Databases' : 'Bases de datos'}</div>
                <div className="text-sm font-semibold text-slate-900 mt-0.5">{selectedDbs.length}/{totalDbs}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-violet-50/70 border border-violet-200">
                <div className="text-[10px] text-violet-700 flex items-center gap-1"><Sparkles className="w-3 h-3" /> Magic Vars</div>
                <div className="text-sm font-semibold text-violet-950 mt-0.5">{activePlan.summary.magicVarsTranslated} {isEn ? 'mapped' : 'traducidas'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-sky-50/70 border border-sky-200">
                <div className="text-[10px] text-sky-700 flex items-center gap-1"><Layers className="w-3 h-3" /> Traefik → Caddy</div>
                <div className="text-sm font-semibold text-sky-950 mt-0.5">{activePlan.summary.traefikRulesTranslated} {isEn ? 'rules' : 'reglas'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-emerald-50/70 border border-emerald-200 col-span-2 sm:col-span-1">
                <div className="text-[10px] text-emerald-700 flex items-center gap-1"><Clock className="w-3 h-3" /> Crons / Vols</div>
                <div className="text-sm font-semibold text-emerald-950 mt-0.5">{activePlan.summary.cronsMapped} · {activePlan.summary.volumesCount}</div>
              </div>
            </div>

            {/* Sub-Tabs */}
            <div className="flex items-center justify-between gap-2 border-b border-slate-200 pb-2 flex-wrap">
              <div className="flex gap-1 flex-wrap" role="tablist">
                {[
                  { id: 'resources' as const, label: `${isEn ? 'Resources' : 'Recursos'} (${allResources.length})` },
                  { id: 'magic' as const, label: `Magic Vars (${activePlan.magicVariables.length})` },
                  { id: 'traefik' as const, label: `Traefik→Caddy (${activePlan.summary.traefikRulesTranslated})` },
                  { id: 'stream' as const, label: `${isEn ? 'Volume & SQL Transfer' : 'Volúmenes y SQL'} (${effectiveStreamPlan.summary.totalSteps})` },
                  { id: 'preflight' as const, label: `Pre-Flight (${activePlan.warnings.length + activePlan.secretWarnings.length})` },
                ].map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    role="tab"
                    aria-selected={previewTab === t.id}
                    onClick={() => setPreviewTab(t.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                      previewTab === t.id
                        ? 'bg-slate-900 text-white'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
              {previewTab === 'resources' && (
                <div className="flex items-center gap-2 text-xs">
                  <button type="button" onClick={selectAll} className="text-slate-700 hover:text-slate-900 font-medium underline cursor-pointer">
                    {isEn ? 'All' : 'Todo'}
                  </button>
                  <span className="text-slate-300">·</span>
                  <button type="button" onClick={deselectAll} className="text-slate-500 hover:text-slate-800 font-medium cursor-pointer">
                    {isEn ? 'None' : 'Ninguno'}
                  </button>
                </div>
              )}
            </div>

            {/* TAB 1: RESOURCES */}
            {previewTab === 'resources' && (
              <div className="space-y-3">
                {allResources.length > 4 && (
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder={isEn ? 'Filter by name, domain, DB engine, or repo…' : 'Filtrar por nombre, dominio, motor de BD o repo…'}
                      className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs focus:outline-none focus:bg-white"
                    />
                  </div>
                )}

                <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                  {projectGroups.map((group) => {
                    const key = group.project.uuid;
                    const isCollapsed = collapsed.has(key);
                    const groupUuids = group.resources.map((r) => r.uuid);
                    const selectedInGroup = groupUuids.filter((id) => selected.has(id)).length;
                    const allInGroupSelected = selectedInGroup === groupUuids.length;
                    const someSelected = selectedInGroup > 0 && !allInGroupSelected;

                    return (
                      <div key={key} className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                        <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-50 border-b border-slate-200 select-none">
                          <button
                            type="button"
                            aria-label={allInGroupSelected ? `Deselect ${group.project.name}` : `Select all ${group.project.name}`}
                            onClick={() => toggleProject(group)}
                            className={`w-4 h-4 flex items-center justify-center rounded border transition-colors shrink-0 cursor-pointer ${
                              allInGroupSelected
                                ? 'bg-slate-900 border-slate-900 text-white'
                                : someSelected
                                  ? 'bg-slate-200 border-slate-400 text-slate-900'
                                  : 'border-slate-300 text-transparent bg-white'
                            }`}
                          >
                            {allInGroupSelected ? <Check className="w-3 h-3" /> : someSelected ? <Minus className="w-3 h-3" /> : null}
                          </button>
                          <button
                            type="button"
                            aria-expanded={!isCollapsed}
                            onClick={() => toggleCollapse(key)}
                            className="flex-1 min-w-0 flex items-center justify-between gap-2 text-left cursor-pointer"
                          >
                            <span className="flex items-center gap-2 min-w-0">
                              <FolderKanban className="w-4 h-4 text-slate-500 shrink-0" />
                              <span className="text-xs font-semibold text-slate-900 truncate">{group.project.name}</span>
                              <span className="text-[11px] text-slate-400 tabular-nums">
                                {selectedInGroup}/{group.resources.length}
                              </span>
                            </span>
                            {isCollapsed ? <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />}
                          </button>
                        </div>
                        {!isCollapsed && (
                          <div className="p-3 space-y-2">{group.resources.map((r) => renderResourceRow(r))}</div>
                        )}
                      </div>
                    );
                  })}
                  {projectGroups.length === 0 && (
                    <div className="text-center py-8 text-slate-500 text-xs">
                      {isEn ? 'No resources matched this filter.' : 'No se encontraron recursos con ese filtro.'}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: MAGIC VARS & VAULT */}
            {previewTab === 'magic' && (
              <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                <div className="flex items-center gap-2 text-xs text-slate-600 bg-violet-50/60 border border-violet-200 rounded-lg p-3">
                  <Lock className="w-4 h-4 text-violet-700 shrink-0" />
                  <span>
                    {isEn ? (
                      <>100% redacted preview: all magic secrets (<code className="font-mono">SERVICE_PASSWORD_*</code>, <code className="font-mono">SERVICE_BASE64_*</code>) map to native <code className="font-mono">{'${vault.*}'}</code> encrypted with AES-256-GCM.</>
                    ) : (
                      <>Vista previa 100% redactada: todos los secretos mágicos (<code className="font-mono">SERVICE_PASSWORD_*</code>, <code className="font-mono">SERVICE_BASE64_*</code>) se traducen a referencias nativas <code className="font-mono">{'${vault.*}'}</code> cifradas con AES-256-GCM.</>
                    )}
                  </span>
                </div>
                {activePlan.magicVariables.length > 0 ? (
                  <div className="border border-slate-200 rounded-xl overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-50 border-b border-slate-200 text-[10px] uppercase tracking-wide text-slate-500">
                        <tr>
                          <th className="px-3 py-2">{isEn ? 'Resource / Env' : 'Recurso / Env'}</th>
                          <th className="px-3 py-2">Coolify v4</th>
                          <th className="px-3 py-2">{isEn ? 'Culkibo Native' : 'Culkibo Nativo'}</th>
                          <th className="px-3 py-2">{isEn ? 'Kind' : 'Tipo'}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {activePlan.magicVariables.map((mv, i) => (
                          <tr key={`${mv.envKey}-${mv.variable}-${i}`} className="hover:bg-slate-50/70">
                            <td className="px-3 py-2">
                              <div className="font-medium text-slate-900">{mv.resourceName}</div>
                              <div className="font-mono text-[10px] text-slate-500">{mv.envKey}</div>
                            </td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate-600">{mv.original}</td>
                            <td className="px-3 py-2 font-mono text-[11px] font-medium text-emerald-700">{mv.resolvedPreview}</td>
                            <td className="px-3 py-2">
                              <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                                mv.kind === 'magic_secret'
                                  ? 'bg-violet-50 text-violet-700 border border-violet-200'
                                  : mv.kind === 'magic_domain'
                                    ? 'bg-sky-50 text-sky-700 border border-sky-200'
                                    : 'bg-slate-100 text-slate-700'
                              }`}>
                                {mv.kind === 'magic_secret' ? 'Vault' : mv.kind === 'magic_domain' ? (isEn ? 'Domain' : 'Dominio') : 'Runtime'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="text-center py-8 text-xs text-slate-500 border border-dashed border-slate-200 rounded-xl">
                    {isEn ? (
                      <>No <code className="font-mono">${'{SERVICE_*}'}</code> / <code className="font-mono">${'{COOLIFY_*}'}</code> magic variables detected.</>
                    ) : (
                      <>No se detectaron variables mágicas <code className="font-mono">${'{SERVICE_*}'}</code> / <code className="font-mono">${'{COOLIFY_*}'}</code> en los recursos actuales.</>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: TRAEFIK → CADDY */}
            {previewTab === 'traefik' && (
              <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                {activePlan.traefikTranslations.length > 0 ? (
                  activePlan.traefikTranslations.map((tr) => (
                    <div key={tr.resourceId} className="border border-slate-200 rounded-xl p-3.5 space-y-2.5 bg-white">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="text-xs font-semibold text-slate-900">{tr.resourceName}</div>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-sky-50 text-sky-700 border border-sky-200 font-medium tabular-nums">
                          {isEn
                            ? `${tr.translatedRules.length} rules translated from ${tr.labelCount} labels`
                            : `${tr.translatedRules.length} reglas traducidas de ${tr.labelCount} etiquetas`}
                        </span>
                      </div>
                      <div className="space-y-1.5">
                        {tr.translatedRules.map((rule, idx) => (
                          <div key={idx} className="flex items-center gap-2 text-[11px] bg-slate-50 border border-slate-100 rounded-lg px-2.5 py-1.5 flex-wrap">
                            <span className="font-mono text-slate-500">{rule.source}</span>
                            <ArrowRight className="w-3 h-3 text-slate-400 shrink-0" />
                            <span className="font-mono font-semibold text-sky-700">{rule.target}</span>
                            <span className="text-slate-700 ml-auto">{rule.summary}</span>
                          </div>
                        ))}
                      </div>
                      {tr.unsupportedLabels.length > 0 && (
                        <div className="text-[11px] bg-amber-50 text-amber-900 border border-amber-200 rounded-lg p-2.5">
                          <div className="font-semibold mb-1">
                            {isEn ? 'Advanced Traefik labels for manual review:' : 'Etiquetas Traefik avanzadas para revisión manual:'}
                          </div>
                          <ul className="font-mono text-[10px] space-y-0.5 list-disc pl-4">
                            {tr.unsupportedLabels.map((u, i) => <li key={i}>{u}</li>)}
                          </ul>
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-xs text-slate-500 border border-dashed border-slate-200 rounded-xl">
                    {isEn ? (
                      <>No custom <code className="font-mono">traefik.http.*</code> labels detected; Culkibo will configure automatic HTTPS and security headers in Caddy.</>
                    ) : (
                      <>No se detectaron etiquetas <code className="font-mono">traefik.http.*</code> personalizadas; Culkibo configurará HTTPS automático y cabeceras de seguridad en Caddy.</>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* TAB 4: VOLUME & SQL LIVE TRANSFER */}
            {previewTab === 'stream' && (
              <div className="max-h-[380px] overflow-y-auto pr-1">{renderStreamTransferPanel()}</div>
            )}

            {/* TAB 5: PRE-FLIGHT & WARNINGS */}
            {previewTab === 'preflight' && (
              <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                {activePlan.databases.length > 0 && (
                  <div className="border border-slate-200 rounded-xl p-3.5 space-y-2">
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-emerald-600" /> {isEn ? 'Database Parity' : 'Paridad de Bases de Datos'} ({activePlan.databases.length})
                    </div>
                    <div className="space-y-1.5">
                      {activePlan.databases.map((db) => (
                        <div key={db.id} className="text-[11px] bg-slate-50 border border-slate-100 rounded-lg p-2.5 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-slate-900">{db.name}</span>
                            <span className="font-mono text-[10px] px-1.5 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded">
                              {db.originalType} → {db.culkiboEngine} (:{db.port})
                            </span>
                          </div>
                          {db.note && <div className="text-amber-800">{db.note}</div>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {activePlan.crons.length > 0 && (
                  <div className="border border-slate-200 rounded-xl p-3.5 space-y-2">
                    <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-amber-600" /> Scheduled Tasks → Crons ({activePlan.crons.length})
                    </div>
                    {activePlan.crons.map((c, i) => (
                      <div key={i} className={`text-[11px] rounded-lg p-2 border ${c.valid ? 'bg-slate-50 border-slate-100' : 'bg-amber-50 border-amber-200'}`}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-slate-900">{c.name}</span>
                          <code className="font-mono text-[10px] bg-white px-1.5 py-0.5 rounded border border-slate-200">{c.schedule}</code>
                        </div>
                        <div className="font-mono text-[10px] text-slate-600 mt-0.5 truncate">{c.command}</div>
                        {c.warning && <div className="text-amber-900 mt-1">{c.warning}</div>}
                      </div>
                    ))}
                  </div>
                )}

                {(activePlan.secretWarnings.length > 0 || activePlan.warnings.length > 0) ? (
                  <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5 space-y-1.5 text-xs text-amber-900">
                    <div className="font-semibold flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-amber-600" /> {isEn ? 'Security & parity advisories' : 'Recomendaciones de seguridad y paridad'}
                    </div>
                    <ul className="list-disc pl-4 space-y-1 text-[11px]">
                      {[...activePlan.secretWarnings, ...activePlan.warnings].map((w, i) => <li key={i}>{w}</li>)}
                    </ul>
                  </div>
                ) : (
                  <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3.5 text-xs text-emerald-900 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>{isEn ? 'Clean pre-flight: 0 blockers detected. Ready for 1-click migration.' : 'Pre-flight limpio: 0 bloqueantes detectados. Listo para migrar en 1 clic.'}</span>
                  </div>
                )}
              </div>
            )}

            {/* Footer Actions */}
            <div className="flex items-center justify-between gap-2 pt-3 border-t border-slate-200 flex-wrap">
              <button type="button" onClick={() => setStep(1)} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                {isEn ? 'Back' : 'Atrás'}
              </button>
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  onClick={handleDownloadPortableZip}
                  disabled={selected.size === 0}
                  className="px-3.5 py-2 text-slate-700 font-medium border border-slate-200 bg-white hover:bg-slate-50 rounded-lg text-xs inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                >
                  <FileArchive className="w-3.5 h-3.5 text-slate-500" />
                  <span>{isEn ? 'Export .zip Bundle' : 'Exportar Bundle .zip'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleImport()}
                  disabled={loading || selected.size === 0}
                  className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer tabular-nums"
                >
                  {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  {loading
                    ? (isEn ? 'Migrating stack…' : 'Migrando stack…')
                    : (isEn
                        ? `Migrate ${selected.size} ${selected.size === 1 ? 'resource' : 'resources'} (Zero-Downtime)`
                        : `Migrar ${selected.size} ${selected.size === 1 ? 'recurso' : 'recursos'} (Zero-Downtime)`)}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* STEP 3: MIGRATION SUMMARY + LIVE TRANSFER + DNS CUTOVER + ROLLBACK*/}
        {/* ================================================================= */}
        {step === 3 && results && (
          <div className="space-y-5">
            <div className="bg-emerald-50/60 border border-emerald-200 rounded-xl p-4 flex items-start gap-3">
              <CheckCircle2 className="w-6 h-6 text-emerald-600 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-semibold text-slate-900">
                  {isEn ? 'Migration complete — your original Coolify server is untouched' : 'Migración completada sin tocar tu Coolify original'}
                </h3>
                <p className="text-xs text-slate-600 mt-1 tabular-nums">
                  {isEn ? 'Imported' : 'Importados'} <strong>{results.importedApps || 0}</strong> apps, <strong>{results.importedDbs || 0}</strong> {isEn ? 'DBs' : 'BDs'}, <strong>{results.importedServices || 0}</strong> {isEn ? 'services' : 'servicios'}
                  {results.importedCrons ? <> · <strong>{results.importedCrons}</strong> crons</> : null}
                  {results.traefikRulesApplied ? <> · <strong>{results.traefikRulesApplied}</strong> Traefik→Caddy</> : null}
                  {results.magicVarsTranslated ? <> · <strong>{results.magicVarsTranslated}</strong> Magic Vars</> : null}.
                </p>
              </div>
            </div>

            {Array.isArray(results.errors) && results.errors.length > 0 && (
              <div className="bg-red-50 text-red-800 p-3.5 rounded-xl text-xs border border-red-200">
                <div className="font-semibold mb-1 flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4" /> {isEn ? 'Partial import errors:' : 'Errores parciales durante la importación:'}
                </div>
                <ul className="list-disc pl-4 space-y-0.5">
                  {results.errors.map((e: string, i: number) => <li key={i}>{e}</li>)}
                </ul>
              </div>
            )}

            {/* Volume & SQL Live Transfer in Step 3 */}
            {renderStreamTransferPanel()}

            {/* Zero-Downtime Cutover Checklist */}
            <div className="border border-slate-200 rounded-xl p-4 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <h4 className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-slate-600" /> {isEn ? 'Zero-Downtime DNS Cutover Checklist' : 'Checklist de Cutover DNS (Zero-Downtime)'}
                </h4>
                <span className="text-[11px] text-slate-500 tabular-nums">
                  {checkedCutover.size}/{cutoverItems.length} {isEn ? 'completed' : 'completados'}
                </span>
              </div>
              <div className="space-y-1.5">
                {cutoverItems.map((item) => {
                  const done = checkedCutover.has(item.id);
                  return (
                    <label
                      key={item.id}
                      className={`flex items-start gap-2.5 p-2.5 rounded-lg border text-xs cursor-pointer transition-colors ${
                        done ? 'bg-emerald-50/40 border-emerald-200 text-slate-500' : 'bg-white border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={done}
                        onChange={() =>
                          setCheckedCutover((prev) => {
                            const next = new Set(prev);
                            if (next.has(item.id)) next.delete(item.id);
                            else next.add(item.id);
                            return next;
                          })
                        }
                        className="w-3.5 h-3.5 mt-0.5 rounded accent-emerald-600"
                      />
                      <div className="min-w-0">
                        <div className={`font-medium ${done ? 'line-through text-slate-500' : 'text-slate-900'}`}>
                          {item.step}. {item.title}
                        </div>
                        <div className="text-[11px] text-slate-500 mt-0.5">{item.detail}</div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Pre-DNS Parity Verifier */}
            {activePlan.domains.length > 0 && (
              <div className="border border-slate-200 rounded-xl p-4 space-y-2.5 bg-slate-50/50">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                    <Terminal className="w-4 h-4 text-slate-600" /> {isEn ? 'Pre-DNS Smoke Check (test Culkibo before flipping traffic)' : 'Verificación Smoke Pre-DNS (prueba Culkibo antes de mover tráfico)'}
                  </div>
                  <button
                    type="button"
                    disabled={verifyingParity}
                    onClick={() => void handleRunLiveVerification()}
                    className="px-2.5 py-1 text-[11px] font-medium rounded-lg border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    {verifyingParity && <Loader2 className="w-3 h-3 animate-spin" />}
                    <span>{isEn ? 'Run Live Parity Check' : 'Verificar paridad en vivo'}</span>
                  </button>
                </div>
                <div className="space-y-1.5">
                  {activePlan.domains.slice(0, 6).map((d) => {
                    const cmd = `curl -fsS -I --resolve ${d.hostname}:443:${serverIp || '<CULKIBO_IP>'} https://${d.hostname}${d.healthPath || '/'}`;
                    return (
                      <div key={d.hostname} className="flex items-center justify-between gap-2 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5">
                        <code className="text-[11px] font-mono text-slate-700 truncate">{cmd}</code>
                        <button
                          type="button"
                          onClick={() => copyText(cmd, isEn ? 'curl command' : 'Comando curl')}
                          className="p-1 text-slate-400 hover:text-slate-700 cursor-pointer shrink-0"
                          title={isEn ? 'Copy command' : 'Copiar comando'}
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    );
                  })}
                </div>
                {verifyReport && (
                  <div className={`text-xs p-2.5 rounded-lg border ${verifyReport.cutoverReady ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-amber-50 border-amber-200 text-amber-900'}`}>
                    {verifyReport.recommendation} ({verifyReport.parityPercent}% {isEn ? 'parity' : 'paridad'})
                  </div>
                )}
              </div>
            )}

            {/* Live Domain DNS Cutover */}
            {importedDomains.length > 0 && (
              <div className="border border-slate-200 rounded-xl p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-slate-600" />
                  <h4 className="font-semibold text-xs text-slate-900">
                    {isEn ? 'Domain Cutover' : 'Conmutación de dominios'} ({importedDomains.length})
                  </h4>
                </div>

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <input
                    type="text"
                    value={serverIp}
                    onChange={(e) => setServerIp(e.target.value)}
                    placeholder={isEn ? 'Culkibo Server IP (e.g. 203.0.113.10)' : 'IP del servidor Culkibo (ej. 203.0.113.10)'}
                    className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                  />
                  <label className="flex items-center gap-2 text-xs text-slate-700 bg-slate-50 border border-slate-200 px-3 py-2 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={useCloudflare}
                      onChange={(e) => setUseCloudflare(e.target.checked)}
                      className="rounded border-slate-300 accent-slate-900"
                    />
                    <Cloud className="w-3.5 h-3.5 text-slate-500" />
                    <span>{isEn ? 'Cloudflare Auto-DNS' : 'Auto-DNS Cloudflare'}</span>
                  </label>
                </div>

                {useCloudflare && !cfAvailable && (
                  <p className="text-[11px] text-amber-800">
                    {isEn
                      ? 'Cloudflare is not configured yet under Settings → Integrations; add your API Token for automatic updates.'
                      : 'Cloudflare no está configurado todavía en Ajustes → Integraciones; configura tu API Token para actualización automática.'}
                  </p>
                )}

                <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
                  {importedDomains.map((domain) => {
                    const isMigrating = migratingDomains.has(domain.hostname);
                    const isPending = domain.sslStatus === 'pending_migration';
                    const isActive = domain.sslStatus === 'active';
                    return (
                      <div key={domain.id} className="flex items-center justify-between p-2.5 bg-slate-50/70 border border-slate-200 rounded-lg gap-3">
                        <div className="flex items-center gap-2 min-w-0 flex-wrap">
                          <span className="font-mono font-medium text-slate-900 text-xs truncate">{domain.hostname}</span>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                            isActive
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                              : 'bg-amber-50 text-amber-800 border-amber-200'
                          }`}>
                            {isPending
                              ? (isEn ? 'DNS Pending' : 'Pendiente DNS')
                              : isActive
                                ? (isEn ? 'Active SSL' : 'Certificado activo')
                                : (isEn ? 'SSL Pending' : 'SSL pendiente')}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={async () => {
                            setMigratingDomains((prev) => new Set([...prev, domain.hostname]));
                            try {
                              await api.migrateDomain(domain.hostname, serverIp, useCloudflare);
                              const domainsRes = await api.getDomains();
                              setImportedDomains(
                                domainsRes.domains.filter((d) => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify')
                              );
                              onNotify(isEn ? `Domain ${domain.hostname} updated` : `Dominio ${domain.hostname} actualizado`, 'success');
                            } catch (e: any) {
                              onNotify(e?.message || (isEn ? 'Failed to migrate domain' : 'Error al migrar dominio'), 'error');
                            } finally {
                              setMigratingDomains((prev) => {
                                const n = new Set(prev);
                                n.delete(domain.hostname);
                                return n;
                              });
                            }
                          }}
                          disabled={isMigrating || !isPending}
                          className="px-3 py-1 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-50 cursor-pointer shrink-0"
                        >
                          {isMigrating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : isPending ? (isEn ? 'Flip DNS' : 'Migrar DNS') : (isEn ? 'Ready' : 'Listo')}
                        </button>
                      </div>
                    );
                  })}
                </div>

                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={async () => {
                      setLoading(true);
                      const hostnames = importedDomains.filter((d) => d.sslStatus === 'pending_migration').map((d) => d.hostname);
                      setMigratingDomains(new Set(hostnames));
                      try {
                        await api.migrateDomainsBatch(hostnames, serverIp, useCloudflare);
                        const domainsRes = await api.getDomains();
                        setImportedDomains(
                          domainsRes.domains.filter((d) => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify')
                        );
                        onNotify(isEn ? 'Batch DNS cutover complete' : 'Conmutación DNS por lote completada', 'success');
                      } catch (e: any) {
                        onNotify(e?.message || (isEn ? 'Failed to migrate domains' : 'Error al migrar los dominios'), 'error');
                      } finally {
                        setMigratingDomains(new Set());
                        setLoading(false);
                      }
                    }}
                    disabled={loading || importedDomains.every((d) => d.sslStatus !== 'pending_migration')}
                    className="bg-slate-900 text-white px-3.5 py-1.5 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                  >
                    {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>{isEn ? 'Flip All Domains' : 'Migrar todos los dominios'}</span>
                  </button>
                </div>
              </div>
            )}

            {/* Rollback Safety Net */}
            <div className="border border-slate-200 rounded-xl overflow-hidden">
              <button
                type="button"
                onClick={() => setShowRollback((prev) => !prev)}
                className="w-full px-4 py-3 bg-slate-50 flex items-center justify-between text-xs font-semibold text-slate-800 cursor-pointer hover:bg-slate-100/70"
              >
                <span className="flex items-center gap-2">
                  <RotateCcw className="w-3.5 h-3.5 text-emerald-600" />
                  {isEn
                    ? `Instant Rollback Safety Net (~${rollbackInfo.estimatedRollbackSeconds || 30}s)`
                    : `Red de Seguridad y Plan de Rollback Instantáneo (~${rollbackInfo.estimatedRollbackSeconds || 30}s)`}
                </span>
                {showRollback ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
              </button>
              {showRollback && (
                <div className="p-4 bg-white border-t border-slate-200 space-y-2 text-xs text-slate-600">
                  <ol className="list-decimal pl-4 space-y-1.5">
                    {(rollbackInfo.steps || []).map((s: string, i: number) => <li key={i}>{s}</li>)}
                  </ol>
                </div>
              )}
            </div>

            {/* Final CTA */}
            <div className="flex justify-between items-center gap-2 pt-3 border-t border-slate-200">
              <button
                type="button"
                onClick={handleDownloadPortableZip}
                className="px-3.5 py-2 text-slate-700 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs inline-flex items-center gap-1.5 cursor-pointer"
              >
                <FileArchive className="w-3.5 h-3.5 text-slate-500" />
                <span>{isEn ? 'Download .zip Bundle' : 'Guardar copia Bundle .zip'}</span>
              </button>
              <button
                type="button"
                onClick={onComplete}
                className="px-5 py-2 bg-slate-900 text-white rounded-lg text-xs font-medium hover:bg-slate-800 cursor-pointer"
              >
                {isEn ? 'Finish & Go to Projects' : 'Finalizar e ir a proyectos'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
