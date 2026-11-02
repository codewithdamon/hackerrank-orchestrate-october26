#!/usr/bin/env node
/*
 * Ghost Data Still Exists — deterministic offline evidence auditor.
 * Only participant-facing files under dataset/ are used for predictions.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const DATA = path.join(ROOT, 'dataset');
const OUT = path.join(ROOT, 'output.csv');
const OP_ORDER = {
  REPORT_REMAINING_RECORD: 0, REPORT_EXPOSED_PII: 1, REPORT_ACTIVE_DATA_FLOW: 2,
  REPORT_RESTORE_RISK: 3, DISABLE_DATA_FLOW: 0, BLOCK_RESTORE: 1,
  DELETE_RECORD: 2, REDACT_RECORD: 3, ANONYMIZE_RECORD: 4,
  VERIFY_RECORD_ABSENT: 0, VERIFY_RECORD_PRESENT: 1, VERIFY_RECORD_REDACTED: 2,
  VERIFY_RECORD_ANONYMIZED: 3, VERIFY_DATA_FLOW_DISABLED: 4, VERIFY_RESTORE_BLOCKED: 5,
};
const ALLOWED = {
  FINDING: { REPORT_REMAINING_RECORD: 'PRESENT', REPORT_EXPOSED_PII: 'PRESENT', REPORT_ACTIVE_DATA_FLOW: 'ACTIVE', REPORT_RESTORE_RISK: 'ACTIVE' },
  REMEDIATION: { DISABLE_DATA_FLOW: 'DISABLED', BLOCK_RESTORE: 'BLOCKED', DELETE_RECORD: 'ABSENT', REDACT_RECORD: 'REDACTED', ANONYMIZE_RECORD: 'ANONYMIZED' },
  VERIFICATION: { VERIFY_RECORD_ABSENT: 'ABSENT', VERIFY_RECORD_PRESENT: 'PRESENT', VERIFY_RECORD_REDACTED: 'REDACTED', VERIFY_RECORD_ANONYMIZED: 'ANONYMIZED', VERIFY_DATA_FLOW_DISABLED: 'DISABLED', VERIFY_RESTORE_BLOCKED: 'BLOCKED' },
};

function readCsv(file) {
  const s = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
  const rows = []; let row = [], field = '', quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) { if (c === '"' && s[i + 1] === '"') { field += '"'; i++; } else if (c === '"') quoted = false; else field += c; }
    else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const header = rows.shift() || [];
  return rows.filter(r => r.some(x => x !== '')).map(r => Object.fromEntries(header.map((h, i) => [h, r[i] || ''])));
}
function csvEscape(v) { const s = String(v ?? ''); return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }
function isoMs(v) { const n = Date.parse(v || ''); return Number.isFinite(n) ? n : -Infinity; }
function normalize(v) {
  if (v == null) return '';
  const s = String(v).trim().toLowerCase();
  if (s.includes('@')) return s;
  if (/^[+()\d\s.-]+$/.test(s) && /\d{7,}/.test(s)) return s.replace(/\D/g, '');
  return s;
}
function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function exactIdentifierInText(text, identifier) {
  const id = String(identifier || '').trim(); if (!id) return false;
  const source = String(text);
  if (!/^\d{7,}$/.test(id) && !source.toLowerCase().includes(id.toLowerCase())) return false;
  if (id.includes('@')) return new RegExp(`(?<![a-z0-9._%+-])${escapeRegExp(id)}(?![a-z0-9.-])`, 'i').test(source);
  if (/^\d{7,}$/.test(id)) return new RegExp(`(?<!\\d)${escapeRegExp(id)}(?!\\d)`).test(source.replace(/\D/g, ' '));
  const re = new RegExp(`(^|[^\\p{L}\\p{N}])${escapeRegExp(id)}($|[^\\p{L}\\p{N}])`, 'iu');
  return re.test(source);
}
function walkObjects(x, visit, context = []) {
  if (Array.isArray(x)) { for (const v of x) walkObjects(v, visit, context); return; }
  if (!x || typeof x !== 'object') return;
  visit(x, context);
  const labels = ['collection','collection_name','data_store','origin_system','source','service','system','record_type'].map(k => x[k]).filter(v => typeof v === 'string');
  for (const [k, v] of Object.entries(x)) if (v && typeof v === 'object') walkObjects(v, visit, context.concat(labels, k));
}
function collectStrings(x, out = []) {
  if (Array.isArray(x)) for (const v of x) collectStrings(v, out);
  else if (x && typeof x === 'object') for (const [k, v] of Object.entries(x)) { if (v != null && typeof v !== 'object') out.push([k, String(v)]); else collectStrings(v, out); }
  return out;
}
function splitSqlValues(s) {
  const out = []; let buf = '', quote = '', depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) { buf += c; if (c === quote) { if (s[i + 1] === quote) buf += s[++i]; else quote = ''; } }
    else if (c === "'" || c === '"') { quote = c; buf += c; }
    else if (c === '(' || c === '[' || c === '{') { depth++; buf += c; }
    else if (c === ')' || c === ']' || c === '}') { depth--; buf += c; }
    else if (c === ',' && depth === 0) { out.push(buf.trim()); buf = ''; }
    else buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}
function sqlLiteral(s) {
  if (/^NULL$/i.test(s)) return null;
  if (/^'.*'$/.test(s)) return s.slice(1, -1).replace(/''/g, "'");
  if (/^".*"$/.test(s)) return s.slice(1, -1).replace(/""/g, '"');
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  return s;
}
function parseSql(text) {
  const tableCols = new Map(), rows = [];
  for (const m of text.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`']?([\w]+)["`']?\s*\(([\s\S]*?)\)\s*;/gi)) {
    const cols = []; for (const line of m[2].split(/,(?![^()]*\))/)) { const c = line.trim().match(/^["`']?([\w]+)["`']?\s+(?:TEXT|INTEGER|REAL|BLOB|NUMERIC)/i); if (c) cols.push(c[1]); }
    if (cols.length) tableCols.set(m[1], cols);
  }
  for (const m of text.matchAll(/INSERT\s+INTO\s+["`']?([\w]+)["`']?\s*(?:\(([^)]*)\))?\s*VALUES\s*\(([\s\S]*?)\)\s*;/gi)) {
    const table = m[1], cols = m[2] ? m[2].split(',').map(x => x.trim().replace(/["`']/g, '')) : tableCols.get(table) || [];
    const vals = splitSqlValues(m[3]).map(sqlLiteral); const obj = { _table: table };
    cols.forEach((c, i) => obj[c] = vals[i]);
    if (obj.record_json) { try { Object.assign(obj, JSON.parse(obj.record_json)); } catch {} }
    rows.push(obj);
  }
  return rows;
}
function parseLogLine(line) {
  line = line.replace(/^\s*[-*]\s*(?=\d{4}-\d\d-\d\dT)/, '');
  const o = {};
  const json = line.match(/\{.*\}/);
  if (json) { try { Object.assign(o, JSON.parse(json[0])); } catch {} }
  const kv = /([\w.-]+)=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s|,]+)/g;
  for (const m of line.matchAll(kv)) { let v = m[2]; if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1); o[m[1]] ??= v; }
  if (o.message && typeof o.message === 'string') {
    const nested = parseLogLine(o.message); for (const [k,v] of Object.entries(nested)) o[k] ??= v;
  }
  const bracketService = line.match(/\[([a-z][a-z0-9_]*(?:service|platform|router|management))\]/i);
  if (bracketService) o.service ??= bracketService[1];
  // RFC5424-style evidence lines place the emitting service after the host token.
  // Prefer this per-event source over the name of a bundled multi-system log file.
  const syslogService = line.match(/^\s*(?:\d{4}-\d\d-\d\dT\S+\s+)?<\d+>\d+\s+\S+\s+([a-z][a-z0-9_-]*(?:_service|_platform))\s+/i);
  if (syslogService) o.service ??= syslogService[1];
  const eventName = line.match(/\b([a-z][a-z0-9_]*(?:_started|_completed|_read|_lookup|_scan|_query|_found|_deleted|_disabled|_enabled|_blocked|_restored|_anonymized|_redacted))\b/i);
  if (eventName) o.event ??= eventName[1];
  const pipes = line.split('|').map(x => x.trim());
  if (pipes.length >= 6 && /^\d{4}-\d\d-\d\dT/.test(pipes[0])) {
    o._event_time ??= pipes[0]; o.system ??= pipes[1]; o.resource_id ??= pipes[2];
    o.record_type ??= pipes[3]; o.result ??= pipes[4]; o.subject_reference ??= pipes.slice(5).join('|');
  }
  const ts = line.match(/\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\b/); if (ts) o._event_time = ts[0];
  const resource = line.match(/\b(?:account|search|cache|support|attachment|analytics|export|backup|data_flow|audit_record|marketing|telemetry|delivery|legal_hold|tombstone|identifier)_\d+\b/i);
  if (resource) o.resource_id ??= resource[0];
  return o;
}
function decodeAscii85(input) {
  const s = input.replace(/\s/g, '').replace(/^<~/, '').replace(/~>$/, '');
  const out = [];
  for (let i = 0; i < s.length;) {
    if (s[i] === 'z') { out.push(0,0,0,0); i++; continue; }
    let group = s.slice(i, i + 5); i += 5;
    const original = group.length; if (original < 2) break;
    while (group.length < 5) group += 'u';
    let value = 0;
    for (const ch of group) value = value * 85 + ch.charCodeAt(0) - 33;
    const bytes = [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
    out.push(...bytes.slice(0, original - 1));
  }
  return Buffer.from(out);
}
function decodePdfLiteral(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '\\') { out += s[i]; continue; }
    const n = s[++i];
    if (n === undefined) break;
    if (/[0-7]/.test(n)) {
      let oct = n;
      while (oct.length < 3 && /[0-7]/.test(s[i + 1] || '')) oct += s[++i];
      out += String.fromCharCode(parseInt(oct, 8));
    } else if (n === 'n') out += '\n'; else if (n === 'r') out += '\r';
    else if (n === 't') out += '\t'; else if (n === 'b') out += '\b'; else if (n === 'f') out += '\f';
    else if (n === '\n') {} else if (n === '\r') { if (s[i + 1] === '\n') i++; }
    else out += n;
  }
  return out;
}
function extractPdfStrings(stream) {
  const out = [];
  for (let i = 0; i < stream.length; i++) {
    if (stream[i] === '(') {
      let depth = 1, body = '', escaped = false;
      for (i++; i < stream.length && depth; i++) {
        const c = stream[i];
        if (escaped) { body += `\\${c}`; escaped = false; continue; }
        if (c === '\\') { escaped = true; continue; }
        if (c === '(') { depth++; body += c; continue; }
        if (c === ')') { depth--; if (depth) body += c; continue; }
        body += c;
      }
      out.push(decodePdfLiteral(body));
    } else if (stream[i] === '<' && stream[i + 1] !== '<') {
      const end = stream.indexOf('>', i + 1);
      if (end > i + 1) {
        const hex = stream.slice(i + 1, end).replace(/\s/g, '');
        if (/^[\da-f]+$/i.test(hex) && hex.length % 2 === 0) out.push(Buffer.from(hex, 'hex').toString('latin1'));
        i = end;
      }
    }
  }
  return out;
}
function extractPdfText(buffer) {
  const raw = buffer.toString('latin1'), pieces = [];
  let pos = 0;
  while ((pos = raw.indexOf('stream\n', pos)) >= 0) {
    const start = pos + 7, end = raw.indexOf('endstream', start);
    if (end < 0) break;
    const objStart = raw.lastIndexOf(' obj', pos);
    const lineStart = objStart < 0 ? -1 : raw.lastIndexOf('\n', objStart - 1);
    const dict = lineStart < 0 ? raw.slice(0, pos) : raw.slice(lineStart + 1, pos);
    let data = Buffer.from(raw.slice(start, end).replace(/[\r\n]+$/, ''), 'latin1');
    const filters = [...dict.matchAll(/\/(ASCII85Decode|A85|ASCIIHexDecode|AHx|FlateDecode|Fl)\b/g)].map(m => m[1]);
    try {
      for (const filter of filters) {
        if (filter === 'ASCII85Decode' || filter === 'A85') data = decodeAscii85(data.toString('latin1'));
        else if (filter === 'ASCIIHexDecode' || filter === 'AHx') data = Buffer.from(data.toString('latin1').replace(/\s|>/g, ''), 'hex');
        else if (filter === 'FlateDecode' || filter === 'Fl') {
          try { data = zlib.inflateSync(data); } catch { data = zlib.inflateRawSync(data); }
        }
      }
      pieces.push(...extractPdfStrings(data.toString('latin1')));
    } catch { /* ignore unsupported or corrupt streams and continue to other objects */ }
    pos = end + 9;
  }
  return pieces.join(' ');
}
function coalesceLogRecords(lines) {
  const groups = new Map(), ungrouped = [];
  for (const row of lines) {
    const key = row.trace_id || row.requestId || row.request_id || row.correlation_id;
    if (!key) { ungrouped.push(row); continue; }
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  const merged = [];
  for (const rows of groups.values()) {
    rows.sort((a,b)=>isoMs(a._event_time)-isoMs(b._event_time));
    const combined = {};
    for (const row of rows) for (const [k,v] of Object.entries(row)) combined[k]=v;
    combined._trace_events = rows.map(x=>x.event).filter(Boolean).join(',');
    merged.push(combined);
  }
  return [...ungrouped, ...merged];
}

function actionFor(cat, rules) {
  const r = rules.find(x => x.data_category === cat);
  return r?.required_action || null;
}
function canonicalSystem(value) {
  const s = String(value || '').toLowerCase();
  if (/support|attachment_preview/.test(s)) return 'support_platform';
  if (/account|identity/.test(s)) return 'account_service';
  if (/analytics/.test(s)) return 'analytics_platform';
  if (/backup|restore/.test(s)) return 'backup_service';
  if (/export/.test(s)) return 'export_service';
  if (/integration|connector/.test(s)) return 'integration_service';
  if (/search|index/.test(s)) return 'search_service';
  if (/security|audit/.test(s)) return 'security_service';
  if (/marketing/.test(s)) return 'marketing_service';
  if (/cache/.test(s)) return 'cache_service';
  if (/telemetry/.test(s)) return 'product_telemetry';
  return value ? String(value) : '';
}
function inferCategory(rec, context) {
  const classify = type => {
    if (/DATA_FLOW|CONNECTOR|SUBSCRIPTION/.test(type)) return 'DATA_FLOW';
    if (/BACKUP|RESTORE|ARCHIVE/.test(type)) return 'BACKUP_ARCHIVE';
    if (/TOMBSTONE|DELETED_CUSTOMER_REFERENCE/.test(type)) return 'ACCOUNT_TOMBSTONE';
    if (/LEGAL_HOLD/.test(type)) return 'LEGAL_HOLD_RECORD';
    if (/SECURITY_AUDIT|AUDIT_RECORD|SECURITY_AUDIT_RECORD/.test(type)) return 'SECURITY_AUDIT_LOG';
    if (/EMAIL_DELIVERY|DELIVERY_LOG/.test(type)) return 'EMAIL_DELIVERY_LOG';
    if (/MARKETING/.test(type)) return 'MARKETING_PROFILE';
    if (/ATTACHMENT/.test(type)) return 'SUPPORT_ATTACHMENT';
    if (/SUPPORT|TICKET|MESSAGE/.test(type)) return 'SUPPORT_MESSAGE';
    if (/ANALYTIC/.test(type)) return 'ANALYTICS_PROFILE';
    if (/TELEMETRY/.test(type)) return 'PRODUCT_TELEMETRY';
    if (/EXPORT/.test(type)) return 'USER_EXPORT';
    if (/CACHE/.test(type)) return 'CACHE_ENTRY';
    if (/SEARCH|INDEX/.test(type)) return 'SEARCH_INDEX_ENTRY';
    if (/SECONDARY_IDENTIFIER|IDENTIFIER/.test(type)) return 'SECONDARY_IDENTIFIER';
    if (/PROFILE|ACCOUNT|CUSTOMER/.test(type)) return 'USER_PROFILE';
    return null;
  };
  const explicit = String(rec.record_type || rec.data_category || '').toUpperCase();
  if (explicit && classify(explicit)) return classify(explicit);
  const collection = String(rec.collection_name || rec.collection || rec._table || '').toUpperCase();
  if (collection && classify(collection)) return classify(collection);
  const source = String(rec.system || rec.system_id || rec.origin_system || rec.service || '').toUpperCase();
  if (source && classify(source)) return classify(source);
  const resource = String(rec.resource_id || '');
  if (/^data_flow_/i.test(resource)) return 'DATA_FLOW';
  if (/^backup_/i.test(resource)) return 'BACKUP_ARCHIVE';
  if (/^audit_record_/i.test(resource)) return 'SECURITY_AUDIT_LOG';
  const contextual = context.filter(x => !String(x).startsWith('evidence/')).join('_').toUpperCase();
  const fallback = classify(contextual || context.join('_').toUpperCase());
  if (fallback) return fallback;
  return null;
}
function systemFor(rec, cat, context = []) {
  if (rec.system || rec.system_id || rec.origin_system || rec.service) return canonicalSystem(rec.system || rec.system_id || rec.origin_system || rec.service);
  const labels = [rec._table, rec.collection, rec.collection_name, cat, ...context].filter(Boolean).map(String);
  for (const name of ['account_service','analytics_platform','backup_service','export_service','integration_service','search_service','security_service','support_platform','identity_service','marketing_service','cache_service','product_telemetry']) if (labels.some(v => v.toLowerCase() === name)) return name;
  const x = labels.filter(v => !v.startsWith('evidence/')).join('_').toLowerCase();
  if (/identity_service|identity/.test(x)) return 'identity_service';
  if (/account|profile|tombstone/.test(x)) return 'account_service';
  if (/search|index/.test(x)) return 'search_service';
  if (/cache/.test(x)) return 'cache_service';
  if (/support|attachment|message|ticket/.test(x)) return 'support_platform';
  if (/analytics/.test(x)) return 'analytics_platform';
  if (/telemetry/.test(x)) return 'product_telemetry';
  if (/export/.test(x)) return 'export_service';
  if (/backup|restore|archive/.test(x)) return 'backup_service';
  if (/connector|flow|integration/.test(x)) return 'integration_service';
  if (/security|audit|legal/.test(x)) return 'security_service';
  return 'unknown_system';
}
function stateFrom(rec, cat) {
  const result = String(rec.result || rec.status || rec.state || rec.operation_result || '').toUpperCase();
  const event = String(rec.event || rec.event_type || rec.operation || '').toUpperCase();
  const explicit = String(rec.enabled ?? rec.active ?? rec.restore_allowed ?? '').toLowerCase();
  const restoreAllowed = String(rec.restore_allowed ?? '').toLowerCase();
  if (cat === 'DATA_FLOW') return /^(true|1|yes|active|enabled)$/.test(explicit) || /ACTIVE|ENABLED|RUNNING/.test(result) ? 'ACTIVE' : /^(false|0|no|disabled|stopped)$/.test(explicit) || /DISABLED|STOPPED|INACTIVE/.test(result) ? 'INACTIVE' : null;
  if (cat === 'BACKUP_ARCHIVE' && restoreAllowed) return /^(true|1|yes|active|allowed)$/.test(restoreAllowed) ? 'RESTORE_ACTIVE' : /^(false|0|no|disabled|blocked)$/.test(restoreAllowed) ? 'RESTORE_BLOCKED' : null;
  if (cat === 'BACKUP_ARCHIVE') {
    const eligible = String(rec.eligible ?? rec.restore_eligible ?? rec.can_restore ?? '').toLowerCase();
    const deletionBlock = String(rec.deletion_block ?? rec.restore_blocked ?? '').toLowerCase();
    if (/^(true|1|yes)$/.test(eligible) && /^(false|0|no)$/.test(deletionBlock)) return 'RESTORE_ACTIVE';
    if (/^(true|1|yes|blocked)$/.test(deletionBlock) || /^(false|0|no)$/.test(eligible)) return 'RESTORE_BLOCKED';
  }
  if (cat === 'BACKUP_ARCHIVE' && /ACTIVE|ALLOWED|RESTORE_ALLOWED/.test(result)) return 'RESTORE_ACTIVE';
  if (cat === 'BACKUP_ARCHIVE' && /BLOCKED|DISABLED|RESTORE_PROHIBITED/.test(result)) return 'RESTORE_BLOCKED';
  if (/NOT_FOUND|ABSENT|DELETED|NO_HIT|MISS/.test(result) || /NOT_FOUND/.test(event) || String(rec.rows ?? '') === '0' || String(rec.http_status || rec.status_code || '') === '404') return 'ABSENT';
  if (/ANONYM|DEIDENTIF/.test(result) || /ANONYM/.test(event)) return 'ANONYMIZED';
  if (/REDACT/.test(result) || /REDACT/.test(event)) return 'REDACTED';
  if (/FOUND|IDENTIFIABLE|PRESENT|RETAINED|HIT|SUCCESS/.test(result) || /_READ_COMPLETED|_LOOKUP_COMPLETED/.test(event) || (Number(rec.rows) > 0 && /COMPLETED|READ|LOOKUP|QUERY/.test(event))) return 'PRESENT';
  if (cat === 'DATA_FLOW' && /enabled|active/i.test(String(rec.last_delivery_status || ''))) return 'ACTIVE';
  if (['ANALYTICS_PROFILE','PRODUCT_TELEMETRY'].includes(cat) && rec.resource_id) {
    const keys = ['user_id','customer_reference','email','phone','email_hash','full_name','name'];
    const present = keys.filter(k => Object.hasOwn(rec, k));
    if (present.length && present.every(k => /^(?:null|none|unknown|redacted|deleted|n\/a)?$/i.test(String(rec[k] ?? '').trim()))) return 'ANONYMIZED';
  }
  if (rec.resource_id && (hasDirectIdentifiers(rec) || rec.user_id || rec.customer_reference || rec.subject_reference)) return 'PRESENT';
  return null;
}
function hasDirectIdentifiers(rec) {
  const vals = collectStrings(rec);
  return vals.some(([k, v]) => /email|phone|name|hash|lookup_key|matched_value/i.test(k) && v && !/^(null|none|unknown|redacted|deleted|n\/a)$/i.test(v)) ||
    vals.some(([k, v]) => /(message|excerpt|text|detail|content)/i.test(k) && /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(v));
}
function ocrImages(files) {
  if (process.platform !== 'win32' || !files.length) return new Map();
  const script = String.raw`Add-Type -AssemblyName System.Runtime.WindowsRuntime
function Await-WinRT($op,[Type]$t) { $m=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } | Select-Object -First 1; $task=$m.MakeGenericMethod($t).Invoke($null,@($op)); $task.Wait(); return $task.Result }
$paths=ConvertFrom-Json $env:GHOST_IMAGE_PATHS
$ocr=[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]::TryCreateFromUserProfileLanguages()
$out=@()
foreach($p in $paths){ try { $f=Await-WinRT ([Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]::GetFileFromPathAsync($p)) ([Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]); $s=Await-WinRT ($f.OpenAsync([Windows.Storage.FileAccessMode,Windows.Storage,ContentType=WindowsRuntime]::Read)) ([Windows.Storage.Streams.IRandomAccessStream,Windows.Storage.Streams,ContentType=WindowsRuntime]); $d=Await-WinRT ([Windows.Graphics.Imaging.BitmapDecoder,Windows.Graphics.Imaging,ContentType=WindowsRuntime]::CreateAsync($s)) ([Windows.Graphics.Imaging.BitmapDecoder,Windows.Graphics.Imaging,ContentType=WindowsRuntime]); $b=Await-WinRT ($d.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap,Windows.Graphics.Imaging,ContentType=WindowsRuntime]); $r=Await-WinRT ($ocr.RecognizeAsync($b)) ([Windows.Media.Ocr.OcrResult,Windows.Foundation,ContentType=WindowsRuntime]); $out+=@{path=$p;text=$r.Text}; $s.Dispose() } catch {} }
ConvertTo-Json -InputObject @($out) -Compress -Depth 4 | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) }`;
  try {
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const result = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      encoding: 'utf8', windowsHide: true, timeout: 90000,
      env: { ...process.env, GHOST_IMAGE_PATHS: JSON.stringify(files) },
      maxBuffer: 8 * 1024 * 1024,
    }).trim();
    const payload = result.split(/\r?\n/).filter(line => /^[A-Za-z0-9+/]+=*$/.test(line)).pop();
    if (!payload) throw new Error('OCR process returned no result');
    const rows = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    return new Map(rows.filter(x => x.path && x.text).map(x => [path.resolve(x.path), x.text]));
  } catch (e) {
    console.error(`Image OCR unavailable: ${e.message}`);
    return new Map();
  }
}
function extractEvidence(manifest) {
  const records = [];
  const imagePaths = manifest.filter(f => /\.png$/i.test(f.file_path) && fs.existsSync(path.join(DATA, f.file_path))).map(f => path.resolve(DATA, f.file_path));
  const imageText = ocrImages(imagePaths);
  const add = (rec, file, context = []) => {
    if (!rec || typeof rec !== 'object') return;
    const cat = inferCategory(rec, context);
    if (!cat && !rec.resource_id) return;
    const captured = isoMs(file.captured_at);
    const recTime = rec.event_time || rec.recorded_at || rec.captured_at || rec.updated_at || rec.timestamp || rec._event_time || rec.created_at || file.captured_at;
    if (isoMs(recTime) > captured + 86400000) return; // don't let future-dated embedded rows leak into earlier snapshots
    records.push({ raw: rec, category: cat || 'UNKNOWN', system: systemFor(rec, cat, context), resource: String(rec.resource_id || rec.record_id || rec.id || ''), evidence: file.file_id, captured, recordTime: isoMs(recTime), context });
  };
  for (const f of manifest) {
    const p = path.join(DATA, f.file_path);
    if (!fs.existsSync(p)) continue;
    const ext = path.extname(p).toLowerCase();
    try {
      if (ext === '.json') {
        const obj = JSON.parse(fs.readFileSync(p, 'utf8'));
        walkObjects(obj, (x, ctx) => { if (x.resource_id || x.record_type || (x.system && x.result)) add(x, f, [f.file_path, ...ctx]); });
      } else if (ext === '.sql') {
        const text = fs.readFileSync(p, 'utf8');
        for (const x of parseSql(text)) add(x, f, [x._table || 'sql']);
      } else if (ext === '.log' || ext === '.txt' || ext === '.csv') {
        const text = fs.readFileSync(p, 'utf8');
        const lines = ext === '.csv' ? readCsv(p) : coalesceLogRecords(text.split(/\r?\n/).filter(Boolean).map(parseLogLine));
        for (const x of lines) add(x, f, [path.basename(p, ext)]);
      } else if (ext === '.pdf') {
        // Decode common PDF stream filters, including ASCII85+Flate content streams and escaped text.
        const pdfText = extractPdfText(fs.readFileSync(p));
        const name = path.basename(p).toLowerCase();
        let pdfCategory = null;
        if (/legal.*retention|legal_hold/.test(name)) pdfCategory = 'LEGAL_HOLD_RECORD';
        else if (/security.*retention|security.*audit/.test(name)) pdfCategory = 'SECURITY_AUDIT_LOG';
        else if (/attachment|delivery_correction/.test(name)) pdfCategory = 'SUPPORT_ATTACHMENT';
        if (pdfCategory) {
          for (const email of new Set(pdfText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [])) {
            const at = pdfText.toLowerCase().indexOf(email.toLowerCase());
            const near = pdfText.slice(Math.max(0, at - 180), at + email.length + 180);
            const rid = near.match(/\b(?:account|support|attachment|audit_record|legal_hold|security_record|backup|search|analytics|export|data_flow)_\d+\b/i)?.[0] ||
              pdfText.match(/\b(?:account|support|attachment|audit_record|legal_hold|security_record|backup|search|analytics|export|data_flow)_\d+\b/i)?.[0] || '';
            const record = { record_type: pdfCategory, resource_id: rid, email, result: 'FOUND' };
            if (pdfCategory === 'LEGAL_HOLD_RECORD') record.active = /(?:active|open)\s+(?:legal\s+)?hold|hold\s+(?:is\s+)?active/i.test(near);
            if (pdfCategory === 'SECURITY_AUDIT_LOG') record.retention_until = near.match(/\d{4}-\d\d-\d\d(?:T\d\d:\d\d:\d\dZ)?/)?.[0] || '';
            if (rid) add(record, f, ['pdf']);
          }
        }
      } else if (ext === '.png') {
        const recognized = imageText.get(path.resolve(p)) || '';
        // Treat a screenshot as evidence only when OCR exposes a grounded resource ID.
        const resourceIds = [...new Set(recognized.match(/\b(?:data_flow|backup|search|analytics|export|support|attachment|account|audit_record|security_record)_\d+\b/gi) || [])];
        for (const resource of resourceIds) {
          const isFlow = /^data_flow_/i.test(resource), isBackup = /^backup_/i.test(resource);
          const normalizedText = recognized.toLowerCase().replace(/[^a-z0-9]+/g, ' ');
          const activeFlow = isFlow && /\bcontinuous\b/.test(normalizedText) && /\bevents delivered\b/.test(normalizedText);
          const row = { record_type: isFlow ? 'DATA_FLOW' : isBackup ? 'BACKUP_ARCHIVE' : path.basename(p), resource_id: resource, system: isFlow ? 'integration_service' : isBackup ? 'backup_service' : '' };
          if (activeFlow) { row.enabled = true; row.result = 'ACTIVE'; }
          else if (isBackup && /archive|retention|checksum/i.test(recognized)) row.result = 'PRESENT';
          add(row, f, ['image_ocr']);
        }
        // Retain PNG textual chunks as a second, independent extraction path.
        const b = fs.readFileSync(p); const latin = b.toString('latin1');
        const texts = [...latin.matchAll(/(?:tEXt|iTXt|zTXt)([\s\S]{1,500}?)(?:\x00|IDAT)/g)].map(m => m[1].replace(/[^\x20-\x7e]/g, ' ')).join(' ');
        if (texts) add({ record_type: path.basename(p), resource_id: '', _metadata: texts }, f, ['image_metadata']);
      }
    } catch (e) { console.error(`Evidence parse warning ${f.file_id}: ${e.message}`); }
  }
  return records;
}

function authorization(text) {
  const t = String(text || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const nonDelete = /\b(access|accessing|copy of my data|export|download|correct|correction|rectify|update my|change my|marketing opt.?out|unsubscribe|stop marketing|opt.?out|consulta de acceso|acceso a mis datos|corregir|rectificar|exportar|desuscribir|desinscribir|opposition au marketing|acces a mes donnees|corriger|exporter|abmelden|auskunft|berichtigen|widerruf der werbung)\b/;
  const deleteWords = /\b(delet(?:e|ed|ing|ion)|eras(?:e|ed|ing|ure)|remov(?:e|ed|ing|al)|forget|forgotten|close (?:my|this|the) account|terminate my account|destroy my data|eliminat(?:e|ed|ing|ion)|eliminar|eliminacion|eliminacao|borrar|suprimir|cancelar mi cuenta|cerrar mi cuenta|supprimer|suppression|effacer|effacement|radier|loschen|loeschen|loschung|loeschung|entfernen|konto schliessen|cancellare|eliminare|cancellazione|apagar|excluir|deletar|apague|apagar minha conta|eliminer|annuler mon compte)\b/;
  const negativeDeletion = /\b(?:do not|don't|never)\s+(?:delete|erase|remove)\b|\b(?:do not|don't|never)\s+close\s+(?:(?:my|the|this)\s+)?account\b|\bnot\s+(?:asking|requesting|seeking)\s+(?:for\s+)?(?:an?\s+)?(?:account\s+)?(?:deletion|erasure|to\s+(?:delete|erase|remove))\b|\bnot\s+a\s+request\s+to\s+(?:delete|erase|remove)\b|\bwithout\s+(?:deleting|erasing|removing)\b|\bremove\s+me\s+from\s+(?:the\s+)?(?:promotional\s+)?(?:email\s+)?(?:marketing|mailing|promotional)\s+lists?\b/;
  if (negativeDeletion.test(t) || /\bnot requesting deletion\b/.test(t)) return false;
  if (nonDelete.test(t) && !deleteWords.test(t)) return false;
  return deleteWords.test(t) || /削除|消去|完全な削除/.test(String(text || '')) ||
    (/\b(verify|check|confirm|audit|review|inspect)\b/.test(t) && /\b(account|profile|data|request)\b.{0,70}\b(gone|removed|deleted|erased|deletion|erasure)\b/.test(t));
}
function buildIdentityMaps(identities, audits) {
  const byId = new Map(), alias = new Map();
  for (const u of identities) {
    const fields = new Set([u.name, u.email, u.phone, u.email_hash].filter(Boolean).map(normalize));
    byId.set(u.user_id, { user: u, fields });
  }
  for (const a of audits) {
    const s = byId.get(a.user_id); if (!s) continue;
    if (a.old_value) s.fields.add(normalize(a.old_value)); if (a.new_value) s.fields.add(normalize(a.new_value));
  }
  for (const [id, x] of byId) for (const f of x.fields) if (f) { if (!alias.has(f)) alias.set(f, new Set()); alias.get(f).add(id); }
  return { byId, alias };
}
function resolveUser(req, maps) {
  const mail = normalize(req.email), ids = maps.alias.get(mail);
  if (!ids || ids.size !== 1) return null;
  return [...ids][0];
}
function valuesFor(rec) { return collectStrings(rec.raw).map(([k, v]) => normalize(v)).filter(Boolean); }
function evidenceMatches(rec, userId, identifiers, aliases, activityLinks, cutoff) {
  const vals = valuesFor(rec);
  if (vals.includes(normalize(userId))) return true;
  if (vals.some(v => identifiers.has(v))) return true;
  // Free-text message excerpts and log details may contain an exact identifier among other text.
  for (const [key, value] of collectStrings(rec.raw)) {
    if (!value || !/(email|phone|name|message|excerpt|detail|subject|lookup|identifier)/i.test(key)) continue;
    const lower = value.toLowerCase();
    for (const id of identifiers) {
      if (!id || id.length < 6) continue;
      if (id.includes('@') && exactIdentifierInText(lower, id)) return true;
      if (/^\d{7,}$/.test(id) && exactIdentifierInText(value, id)) return true;
      if (!id.includes('@') && !/^\d+$/.test(id) && lower === id) return true;
    }
  }
  const links = rec.resource && activityLinks.get(rec.resource);
  return Boolean(links && links.has(userId) && links.get(userId) <= cutoff);
}
function buildActivityLinks(activity, maps, requests) {
  const link = new Map();
  for (const a of activity) {
    const when = isoMs(a.event_time); if (!a.resource_id) continue;
    const text = [a.details, a.resource_id].join(' ');
    for (const [id, item] of maps.byId) {
      const match = [...item.fields].some(v => (v.includes('@') || /^user_\d+$/i.test(v) || /^[a-f0-9]{40,}$/i.test(v)) && exactIdentifierInText(text, v));
      if (match) { if (!link.has(a.resource_id)) link.set(a.resource_id, new Map()); const prior=link.get(a.resource_id).get(id); if(prior===undefined||when<prior) link.get(a.resource_id).set(id,when); }
    }
  }
  return link;
}
function policyForRecord(r, rules) {
  let action = actionFor(r.category, rules);
  if (r.category === 'SECURITY_AUDIT_LOG') {
    const until = isoMs(r.raw.retention_until || r.raw.retention_expires_at);
    action = Number.isFinite(until) ? (until >= r.caseCutoff ? 'RETAIN' : 'DELETE') : (action || 'RETAIN');
  }
  if (r.category === 'LEGAL_HOLD_RECORD') {
    const active = String(r.raw.active ?? r.raw.legal_hold_active ?? r.raw.status ?? '').toLowerCase();
    action = /true|1|active|held/.test(active) ? 'RETAIN' : 'DELETE';
  }
  if (r.category === 'BACKUP_ARCHIVE') action = 'RETAIN';
  if (r.category === 'DATA_FLOW') action = 'DISABLE';
  return action;
}
function inferLineRecord(x) {
  const r = x.raw, event = String(r.event || r.event_type || '').toLowerCase(), sys = String(r.service || r.system || x.system).toLowerCase();
  let cat = x.category;
  if (!event) return { ...x, system: r.service || r.system || x.system };
  // Multi-system log files can have a misleading filename/category. Explicit event
  // and emitting-service names describe the individual row and must take precedence.
  if (/legacy_contact_index/.test(String(r.source || '').toLowerCase())) cat = 'SECONDARY_IDENTIFIER';
  else if (/contact_lookup/.test(event) && Object.hasOwn(r,'email_opt_in')) cat = 'MARKETING_PROFILE';
  else if (/attachment/.test(event)) cat = 'SUPPORT_ATTACHMENT';
  else if (/message|support|ticket/.test(event)) cat = 'SUPPORT_MESSAGE';
  else if (/analytics/.test(event)) cat = 'ANALYTICS_PROFILE';
  else if (/index|search/.test(event)) cat = 'SEARCH_INDEX_ENTRY';
  else if (/profile_lookup|account_lookup/.test(event)) cat = 'USER_PROFILE';
  else if (/audit/.test(event)) cat = 'SECURITY_AUDIT_LOG';
  else if (/export/.test(event)) cat = 'USER_EXPORT';
  else if (/marketing/.test(event)) cat = 'MARKETING_PROFILE';
  else if (/cache/.test(event)) cat = 'CACHE_ENTRY';
  else if (/connector|sync|import|data_flow/.test(event)) cat = 'DATA_FLOW';
  else if (/backup|restore/.test(event)) cat = 'BACKUP_ARCHIVE';
  else if (/integration|connector|sync/.test(sys)) cat = 'DATA_FLOW';
  else if (/backup|restore/.test(sys)) cat = 'BACKUP_ARCHIVE';
  else if (/search|index/.test(sys)) cat = 'SEARCH_INDEX_ENTRY';
  else if (/cache/.test(sys)) cat = 'CACHE_ENTRY';
  else if (/attachment/.test(sys)) cat = 'SUPPORT_ATTACHMENT';
  else if (/support|ticket/.test(sys)) cat = 'SUPPORT_MESSAGE';
  else if (/analytics/.test(sys)) cat = 'ANALYTICS_PROFILE';
  else if (/marketing/.test(sys)) cat = 'MARKETING_PROFILE';
  else if (/security/.test(sys)) cat = 'SECURITY_AUDIT_LOG';
  else if (/export/.test(sys)) cat = 'USER_EXPORT';
  else if (/account|identity/.test(sys)) cat = 'USER_PROFILE';
  return { ...x, category: cat, system: canonicalSystem(r.service || r.system || x.system || systemFor(r, cat)) };
}
function makeSteps(req, userId, idset, maps, allEvidence, activityLinks, rules, activity, auditRows) {
  const cutoff = isoMs(req.audit_at), records = [];
  const aliases = maps.byId.get(userId)?.fields || idset;
  for (let x of allEvidence) {
    if (x.captured > cutoff || x.recordTime > cutoff) continue;
    x = inferLineRecord(x);
    if (!evidenceMatches(x, userId, idset, aliases, activityLinks, cutoff)) continue;
    const category = x.category;
    if (!category || category === 'UNKNOWN') continue;
    const raw = x.raw;
    const st = stateFrom(raw, category);
    if (!st) continue;
    // An absence lookup predating the deletion request is not proof of the
    // post-request state: the record could have been created again meanwhile.
    if (st === 'ABSENT' && x.recordTime < isoMs(req.requested_at)) continue;
    const action = policyForRecord({ ...x, caseCutoff: cutoff }, rules);
    const direct = hasDirectIdentifiers(raw) || /IDENTIFIABLE/.test(String(raw.result || raw.status || '').toUpperCase());
    let violation = false, finding = null, remedy = null, verify = null, extraVerify = [];
    if (category === 'DATA_FLOW') {
      if (st === 'ACTIVE') { violation = true; finding = 'REPORT_ACTIVE_DATA_FLOW'; remedy = 'DISABLE_DATA_FLOW'; verify = 'VERIFY_DATA_FLOW_DISABLED'; }
      else if (st === 'INACTIVE') verify = 'VERIFY_DATA_FLOW_DISABLED';
    } else if (category === 'BACKUP_ARCHIVE') {
      if (st === 'RESTORE_ACTIVE') { violation = true; finding = 'REPORT_RESTORE_RISK'; remedy = 'BLOCK_RESTORE'; verify = 'VERIFY_RESTORE_BLOCKED'; }
      else if (st === 'RESTORE_BLOCKED') verify = 'VERIFY_RESTORE_BLOCKED';
      else if (st === 'PRESENT' && action === 'RETAIN') verify = 'VERIFY_RECORD_PRESENT';
    } else if (st === 'ABSENT') {
      if (action === 'DELETE') verify = 'VERIFY_RECORD_ABSENT';
    } else if (st === 'PRESENT' || st === 'REDACTED' || st === 'ANONYMIZED') {
      const linked = valuesFor(x).includes(normalize(userId));
      if (action === 'DELETE') { violation = true; finding = 'REPORT_REMAINING_RECORD'; remedy = 'DELETE_RECORD'; verify = 'VERIFY_RECORD_ABSENT'; }
      else if (action === 'REDACT') {
        if (direct) { violation = true; finding = 'REPORT_EXPOSED_PII'; remedy = 'REDACT_RECORD'; verify = 'VERIFY_RECORD_REDACTED'; }
        else verify = 'VERIFY_RECORD_REDACTED';
      } else if (action === 'ANONYMIZE') {
        if (direct || linked) { violation = true; finding = 'REPORT_EXPOSED_PII'; remedy = 'ANONYMIZE_RECORD'; verify = 'VERIFY_RECORD_ANONYMIZED'; }
        else verify = 'VERIFY_RECORD_ANONYMIZED';
      } else if (action === 'RETAIN') verify = 'VERIFY_RECORD_PRESENT';
    } else if (st === 'INACTIVE') verify = null;
    const resource = x.resource || String(raw.resource_id || raw.record_id || '');
    const sys = x.system || systemFor(raw, category, x.context);
    if (violation) {
      if (action === 'DELETE' && raw.source_resource_id) extraVerify.push({ operation: 'VERIFY_RECORD_ABSENT', system: 'account_service', resource: String(raw.source_resource_id) });
      records.push({ category, action, system: sys, resource, evidence: x.evidence, finding, remedy, verify, extraVerify, rank: OP_ORDER[finding], st, raw, captured: x.captured });
    }
    else if (verify) records.push({ category, action, system: sys, resource, evidence: x.evidence, verify, extraVerify, st, raw, captured: x.captured });
  }
  // Resource-identity catalog events are participant-facing evidence of a resource link.
  // They do not establish operation outcomes (delete/sync/restore); only explicit link events
  // are used as a grounded resource-to-subject relationship when no stronger snapshot exists.
  const activityCategory = {
    account_service: 'USER_PROFILE', search_service: 'SEARCH_INDEX_ENTRY', analytics_platform: 'ANALYTICS_PROFILE',
    export_service: 'USER_EXPORT', marketing_platform: 'MARKETING_PROFILE', support_platform: 'SUPPORT_MESSAGE',
    object_storage: 'SUPPORT_ATTACHMENT', security_service: 'SECURITY_AUDIT_LOG', identity_service: 'ACCOUNT_TOMBSTONE',
  };
  for (const a of activity) {
    if (a.event_type !== 'LINK_RESOURCE_IDENTITY' || isoMs(a.event_time) > cutoff || isoMs(a.event_time) < isoMs(req.requested_at)) continue;
    const details = String(a.details || '');
    const activityMatch = exactIdentifierInText(details, userId) || [...idset].some(v => exactIdentifierInText(details, v));
    if (!activityMatch) continue;
    const category = activityCategory[a.target_system]; if (!category || !a.resource_id) continue;
    const foundEmail = [...idset].find(v => v.includes('@') && exactIdentifierInText(details, v));
    const inferredSystem = a.target_system === 'marketing_platform' ? 'marketing_platform' : a.target_system;
    const action = actionFor(category, rules);
    const raw = { resource_id: a.resource_id, user_id: userId, email: foundEmail || null, record_type: category, result: category === 'SECURITY_AUDIT_LOG' ? 'FOUND' : category === 'ANALYTICS_PROFILE' || category === 'SUPPORT_MESSAGE' || category === 'ACCOUNT_TOMBSTONE' ? 'IDENTIFIABLE' : 'FOUND' };
    const finding = action === 'DELETE' ? 'REPORT_REMAINING_RECORD' : action === 'ANONYMIZE' || action === 'REDACT' ? 'REPORT_EXPOSED_PII' : null;
    const remedy = action === 'DELETE' ? 'DELETE_RECORD' : action === 'ANONYMIZE' ? 'ANONYMIZE_RECORD' : action === 'REDACT' ? 'REDACT_RECORD' : null;
    records.push({ category, action, system: inferredSystem, resource: a.resource_id, evidence: a.activity_id,
      finding, remedy, verify: action === 'DELETE' ? 'VERIFY_RECORD_ABSENT' : action === 'ANONYMIZE' ? 'VERIFY_RECORD_ANONYMIZED' : action === 'REDACT' ? 'VERIFY_RECORD_REDACTED' : 'VERIFY_RECORD_PRESENT',
      extraVerify: [], st: 'PRESENT', raw, captured: isoMs(a.event_time), recordTime: isoMs(a.event_time) });
  }
  // Deduplicate repeated representations of the same resource; prefer its latest evidence state.
  const grouped = new Map();
  for (const r of records) {
    const key = [r.category, r.system, r.resource || `${r.evidence}:${JSON.stringify(r.raw).slice(0,100)}`].join('|');
    const old = grouped.get(key);
    if (!old || r.captured > old.captured || (r.captured === old.captured && r.recordTime > old.recordTime)) grouped.set(key, r);
  }
  const items = [...grouped.values()];
  const violations = items.filter(x => x.finding);
  const findings = violations.map(x => step('FINDING', x.finding, x.system, x.resource, x.evidence));
  const remediations = violations.filter(x => x.remedy).map(x => step('REMEDIATION', x.remedy, x.system, x.resource, ''));
  const future = violations.flatMap(x => [
    ...(x.verify ? [step('VERIFICATION', x.verify, x.system, x.resource, '')] : []),
    ...(x.extraVerify || []).map(v => typeof v === 'string' ? step('VERIFICATION', v, x.system, x.resource, '') : step('VERIFICATION', v.operation, v.system, v.resource, '')),
  ]);
  const completeChecks = items.filter(x => !x.finding).flatMap(x => [
    ...(x.verify ? [step('VERIFICATION', x.verify, x.system, x.resource, x.evidence)] : []),
    ...(x.extraVerify || []).map(v => typeof v === 'string' ? step('VERIFICATION', v, x.system, x.resource, x.evidence) : step('VERIFICATION', v.operation, v.system, v.resource, x.evidence)),
  ]);
  const ordered = (arr, phase) => arr.sort((a, b) => (OP_ORDER[a.operation] ?? 99) - (OP_ORDER[b.operation] ?? 99) || a.system_id.localeCompare(b.system_id) || a.resource_id.localeCompare(b.resource_id));
  if (violations.length) {
    const checks = [...future, ...completeChecks.map(s => ({ ...s, evidence_id: '' }))];
    const unique = new Map(checks.map(s => [`${s.operation}|${s.system_id}|${s.resource_id}`, s]));
    return { status: 'INCOMPLETE', steps: [...ordered(findings), ...ordered(remediations), ...ordered([...unique.values()])] };
  }
  // If evidence exists for this subject but is too weak to verify a required state, do not fabricate a claim.
  return { status: 'COMPLETE', steps: ordered(completeChecks) };
}
function step(phase, operation, system_id, resource_id, evidence_id) {
  return { phase, system_id: system_id || 'unknown_system', resource_id: resource_id || 'unknown_resource', operation, state: ALLOWED[phase][operation], evidence_id: evidence_id || '' };
}
function classify(req, ctx) {
  if (!authorization(req.request_text)) return { case_id: req.case_id, deletion_status: 'NOT_APPLICABLE', steps: [] };
  const id = resolveUser(req, ctx.maps);
  if (!id) return { case_id: req.case_id, deletion_status: 'INCOMPLETE', steps: [] };
  const aliases = ctx.maps.byId.get(id).fields;
  const result = makeSteps(req, id, aliases, ctx.maps, ctx.evidence, ctx.activityLinks, ctx.rules, ctx.activity, ctx.audits);
  return { case_id: req.case_id, deletion_status: result.status, steps: result.steps };
}
function assignNumbers(rows) {
  return rows.map(r => ({ ...r, steps: r.steps.map((s, i) => ({ step_no: i + 1, phase: s.phase, system_id: s.system_id, resource_id: s.resource_id, operation: s.operation, state: s.state, evidence_id: s.evidence_id })) }));
}
function validateRows(rows, requests, manifest) {
  const errors = [], validIds = new Set(manifest.map(x => x.file_id));
  for (const a of readCsv(path.join(DATA, 'system_activity.csv'))) validIds.add(a.activity_id);
  for (const a of readCsv(path.join(DATA, 'user_audit_log.csv'))) validIds.add(a.audit_id);
  if (rows.length !== requests.length) errors.push(`Expected ${requests.length} rows, got ${rows.length}`);
  const ids = rows.map(x => x.case_id);
  if (new Set(ids).size !== ids.length) errors.push('Duplicate case_id');
  if (ids.join('\n') !== [...ids].sort((a, b) => a.localeCompare(b)).join('\n')) errors.push('case_id ordering invalid');
  const byCase = new Map(requests.map(x => [x.case_id, x]));
  for (const r of rows) {
    if (!byCase.has(r.case_id)) errors.push(`Unknown case ${r.case_id}`);
    if (!['COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'].includes(r.deletion_status)) errors.push(`Invalid status ${r.case_id}`);
    if (r.deletion_status === 'NOT_APPLICABLE' && r.steps.length) errors.push(`NOT_APPLICABLE must have no steps: ${r.case_id}`);
    let phase = -1, previousPhase = -1, last = null;
    for (let i = 0; i < r.steps.length; i++) {
      const s = r.steps[i], p = ['FINDING', 'REMEDIATION', 'VERIFICATION'].indexOf(s.phase);
      if (s.step_no !== i + 1) errors.push(`Step numbering ${r.case_id}`);
      if (p < 0 || p < phase) errors.push(`Phase order ${r.case_id}`); phase = p;
      if (!ALLOWED[s.phase] || !Object.hasOwn(ALLOWED[s.phase], s.operation) || ALLOWED[s.phase][s.operation] !== s.state) errors.push(`Invalid operation/state ${r.case_id}:${i + 1}`);
      const keys = Object.keys(s).sort().join(',');
      if (keys !== ['evidence_id','operation','phase','resource_id','state','step_no','system_id'].sort().join(',')) errors.push(`Invalid step fields ${r.case_id}`);
      if (s.phase === 'FINDING' && !validIds.has(s.evidence_id)) errors.push(`Invalid finding evidence ${r.case_id}:${i + 1}`);
      if (r.deletion_status === 'COMPLETE' && s.phase === 'VERIFICATION' && !validIds.has(s.evidence_id)) errors.push(`Invalid complete verification evidence ${r.case_id}:${i + 1}`);
      if (r.deletion_status === 'INCOMPLETE' && s.phase !== 'FINDING' && s.evidence_id !== '') errors.push(`Future step evidence must be empty ${r.case_id}:${i + 1}`);
      const rank = OP_ORDER[s.operation] ?? 99;
      if (last && p === previousPhase && rank < last.rank) errors.push(`Operation ordering ${r.case_id}`);
      if (last && p === previousPhase && rank === last.rank && (s.system_id.localeCompare(last.system) < 0 || (s.system_id === last.system && s.resource_id.localeCompare(last.resource) < 0))) errors.push(`System/resource ordering ${r.case_id}`);
      if (r.deletion_status === 'COMPLETE' && s.phase !== 'VERIFICATION') errors.push(`COMPLETE may contain only verification ${r.case_id}`);
      last = { rank, system:s.system_id, resource:s.resource_id }; previousPhase = p;
    }
  }
  return errors;
}
function validateOutputFile(file, requests, manifest, activity, audits) {
  const errors = [];
  const parsed = readCsv(file);
  const expected = ['case_id','deletion_status','steps_json'];
  if (!parsed.length || Object.keys(parsed[0]).join(',') !== expected.join(',')) errors.push('Output header/columns do not match the exact contract');
  const rows = [];
  for (const r of parsed) {
    let steps;
    try { steps = JSON.parse(r.steps_json); } catch { errors.push(`Invalid steps_json ${r.case_id}`); steps = []; }
    if (!Array.isArray(steps)) { errors.push(`steps_json is not an array ${r.case_id}`); steps = []; }
    rows.push({ case_id:r.case_id, deletion_status:r.deletion_status, steps });
  }
  errors.push(...validateRows(rows, requests, manifest));
  return errors;
}
function loadContext() {
  const requests = readCsv(path.join(DATA, 'deletion_requests.csv'));
  const identities = readCsv(path.join(DATA, 'user_identities.csv'));
  const audits = readCsv(path.join(DATA, 'user_audit_log.csv'));
  const activity = readCsv(path.join(DATA, 'system_activity.csv'));
  const rules = readCsv(path.join(DATA, 'deletion_rules.csv'));
  const manifest = readCsv(path.join(DATA, 'evidence_files.csv'));
  const maps = buildIdentityMaps(identities, audits);
  const evidence = extractEvidence(manifest);
  const activityLinks = buildActivityLinks(activity, maps, requests);
  return { requests, identities, audits, activity, rules, manifest, maps, evidence, activityLinks };
}
function run() {
  const ctx = loadContext();
  const rows = assignNumbers(ctx.requests.map(r => classify(r, ctx))).sort((a, b) => a.case_id.localeCompare(b.case_id));
  const errors = validateRows(rows, ctx.requests, ctx.manifest);
  if (errors.length) { console.error(`Validation failed (${errors.length}):\n${errors.slice(0, 30).join('\n')}`); process.exitCode = 1; return; }
  const lines = ['case_id,deletion_status,steps_json'];
  for (const r of rows) lines.push([r.case_id, r.deletion_status, JSON.stringify(r.steps)].map(csvEscape).join(','));
  fs.writeFileSync(OUT, lines.join('\n') + '\n', 'utf8');
  const fileErrors = validateOutputFile(OUT, ctx.requests, ctx.manifest, ctx.activity, ctx.audits);
  if (fileErrors.length) { console.error(`Written output failed validation (${fileErrors.length}):\n${fileErrors.slice(0,30).join('\n')}`); process.exitCode=1; return; }
  console.log(`Wrote ${rows.length} cases to ${OUT}; evidence records indexed: ${ctx.evidence.length}`);
  const counts = Object.fromEntries(['COMPLETE','INCOMPLETE','NOT_APPLICABLE'].map(s => [s, rows.filter(x => x.deletion_status === s).length]));
  console.log(JSON.stringify(counts));
  console.log(`Complete rows without evidence verification: ${rows.filter(x=>x.deletion_status==='COMPLETE'&&x.steps.length===0).length}`);
}

if (require.main === module) run();
module.exports = { readCsv, authorization, exactIdentifierInText, buildIdentityMaps, extractEvidence, loadContext, classify, validateRows, validateOutputFile, assignNumbers, inferLineRecord, stateFrom, run };
