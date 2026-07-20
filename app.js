// ============================================================================
// Makkah Health Cluster — Volunteer Management Portal
// Single-file edition. Everything (backend + frontend) lives in this one file.
// Run with:  node app.js
// Requires only Node.js 22.5+ — no npm install, no other files needed.
// ============================================================================
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { URL } = require('node:url');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Auth helpers (password hashing + signed session tokens, node:crypto only)
// ---------------------------------------------------------------------------
const SECRET = process.env.SESSION_SECRET || 'volunteer-mgmt-dev-secret-change-in-production';

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}
function createToken(payload, expiresInSeconds = 60 * 60 * 24 * 7) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds };
  const encoded = base64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  const a = Buffer.from(sig || '', 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(base64urlDecode(encoded));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Certificate PDF generator (hand-rolled, zero dependencies)
// ---------------------------------------------------------------------------
const HELV_BOLD_W = {' ':278,'!':333,'"':474,'#':556,'$':556,'%':889,'&':722,"'":238,'(':333,')':333,'*':389,'+':584,',':278,'-':333,'.':278,'/':278,'0':556,'1':556,'2':556,'3':556,'4':556,'5':556,'6':556,'7':556,'8':556,'9':556,':':333,';':333,'<':584,'=':584,'>':584,'?':611,'@':975,'A':722,'B':722,'C':722,'D':722,'E':667,'F':611,'G':778,'H':722,'I':278,'J':556,'K':722,'L':611,'M':833,'N':722,'O':778,'P':667,'Q':778,'R':722,'S':667,'T':611,'U':722,'V':667,'W':944,'X':667,'Y':667,'Z':611,'[':333,'\\':278,']':333,'^':584,'_':556,'`':333,'a':556,'b':611,'c':556,'d':611,'e':556,'f':333,'g':611,'h':611,'i':278,'j':278,'k':556,'l':278,'m':889,'n':611,'o':611,'p':611,'q':611,'r':389,'s':556,'t':333,'u':611,'v':556,'w':778,'x':556,'y':556,'z':500,'{':389,'|':280,'}':389,'~':584};
const HELV_W = {' ':278,'!':278,'"':355,'#':556,'$':556,'%':889,'&':667,"'":191,'(':333,')':333,'*':389,'+':584,',':278,'-':333,'.':278,'/':278,'0':556,'1':556,'2':556,'3':556,'4':556,'5':556,'6':556,'7':556,'8':556,'9':556,':':278,';':278,'<':584,'=':584,'>':584,'?':556,'@':1015,'A':667,'B':667,'C':722,'D':722,'E':667,'F':611,'G':778,'H':722,'I':278,'J':500,'K':667,'L':556,'M':833,'N':722,'O':778,'P':667,'Q':778,'R':722,'S':667,'T':611,'U':722,'V':667,'W':944,'X':667,'Y':667,'Z':611,'[':278,'\\':278,']':278,'^':469,'_':556,'`':333,'a':556,'b':556,'c':500,'d':556,'e':556,'f':278,'g':556,'h':556,'i':222,'j':222,'k':500,'l':222,'m':833,'n':556,'o':556,'p':556,'q':556,'r':333,'s':500,'t':278,'u':556,'v':500,'w':722,'x':500,'y':500,'z':500,'{':334,'|':260,'}':334,'~':584};

function certSanitize(str) {
  return String(str == null ? '' : str).replace(/[^\x20-\x7E]/g, '').trim();
}
function certTextWidth(str, table, size) {
  let w = 0;
  for (const ch of str) w += table[ch] !== undefined ? table[ch] : 556;
  return (w / 1000) * size;
}
function certEscape(str) {
  return str.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

// ---- Signature image support (JPEG passthrough + minimal PNG decoder, zero deps) ----
function readJpegInfo(buf) {
  if (buf.length < 4 || buf[0] !== 0xFF || buf[1] !== 0xD8) return null;
  let offset = 2;
  while (offset + 4 <= buf.length) {
    if (buf[offset] !== 0xFF) { offset++; continue; }
    let marker = buf[offset + 1];
    while (marker === 0xFF && offset + 2 < buf.length) { offset++; marker = buf[offset + 1]; }
    if (marker === 0xD8 || marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { offset += 2; continue; }
    if (marker === 0xD9 || offset + 3 >= buf.length) break;
    const segLen = buf.readUInt16BE(offset + 2);
    const isSOF = marker >= 0xC0 && marker <= 0xCF && marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC;
    if (isSOF) {
      const height = buf.readUInt16BE(offset + 5);
      const width = buf.readUInt16BE(offset + 7);
      const components = buf[offset + 9];
      return { width, height, components };
    }
    if (marker === 0xDA) break;
    offset += 2 + segLen;
  }
  return null;
}

function decodePNG(buf) {
  if (buf.length < 8 || buf.readUInt32BE(0) !== 0x89504e47 || buf.readUInt32BE(4) !== 0x0d0a1a0a) {
    throw new Error('Not a valid PNG file');
  }
  let offset = 8;
  let width, height, bitDepth, colorType, interlace;
  const idatChunks = [];
  while (offset + 8 <= buf.length) {
    const len = buf.readUInt32BE(offset);
    const type = buf.toString('ascii', offset + 4, offset + 8);
    const dataStart = offset + 8;
    if (type === 'IHDR') {
      width = buf.readUInt32BE(dataStart);
      height = buf.readUInt32BE(dataStart + 4);
      bitDepth = buf[dataStart + 8];
      colorType = buf[dataStart + 9];
      interlace = buf[dataStart + 12];
    } else if (type === 'IDAT') {
      idatChunks.push(buf.subarray(dataStart, dataStart + len));
    } else if (type === 'IEND') {
      break;
    }
    offset = dataStart + len + 4;
  }
  if (!width || !height) throw new Error('Invalid PNG (missing header)');
  if (bitDepth !== 8) throw new Error('Only 8-bit PNG images are supported');
  if (interlace !== 0) throw new Error('Interlaced PNG images are not supported');
  const channelsMap = { 0: 1, 2: 3, 4: 2, 6: 4 };
  const channels = channelsMap[colorType];
  if (!channels) throw new Error('Unsupported PNG color mode (use plain RGB/RGBA, not indexed/palette)');
  const raw = zlib.inflateSync(Buffer.concat(idatChunks));
  const stride = width * channels;
  const out = Buffer.alloc(height * stride);
  let rawOffset = 0;
  for (let y = 0; y < height; y++) {
    const filterType = raw[rawOffset]; rawOffset++;
    const lineStart = y * stride;
    const prevLineStart = (y - 1) * stride;
    for (let x = 0; x < stride; x++) {
      const rawByte = raw[rawOffset + x];
      const a = x >= channels ? out[lineStart + x - channels] : 0;
      const b = y > 0 ? out[prevLineStart + x] : 0;
      const c = y > 0 && x >= channels ? out[prevLineStart + x - channels] : 0;
      let value;
      switch (filterType) {
        case 0: value = rawByte; break;
        case 1: value = (rawByte + a) & 0xff; break;
        case 2: value = (rawByte + b) & 0xff; break;
        case 3: value = (rawByte + Math.floor((a + b) / 2)) & 0xff; break;
        case 4: {
          const p = a + b - c;
          const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          const pr = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
          value = (rawByte + pr) & 0xff;
          break;
        }
        default: throw new Error('Unsupported PNG filter');
      }
      out[lineStart + x] = value;
    }
    rawOffset += stride;
  }
  let rgb, alpha = null;
  if (colorType === 2) {
    rgb = out;
  } else if (colorType === 6) {
    rgb = Buffer.alloc(width * height * 3);
    alpha = Buffer.alloc(width * height);
    for (let i = 0, j = 0, k = 0; i < out.length; i += 4, j += 3, k++) {
      rgb[j] = out[i]; rgb[j + 1] = out[i + 1]; rgb[j + 2] = out[i + 2];
      alpha[k] = out[i + 3];
    }
  } else if (colorType === 0) {
    rgb = Buffer.alloc(width * height * 3);
    for (let i = 0, j = 0; i < out.length; i++, j += 3) { rgb[j] = rgb[j + 1] = rgb[j + 2] = out[i]; }
  } else if (colorType === 4) {
    rgb = Buffer.alloc(width * height * 3);
    alpha = Buffer.alloc(width * height);
    for (let i = 0, j = 0, k = 0; i < out.length; i += 2, j += 3, k++) {
      rgb[j] = rgb[j + 1] = rgb[j + 2] = out[i];
      alpha[k] = out[i + 1];
    }
  }
  return { width, height, rgb, alpha };
}

function buildCertificatePDF({
  orgNameEn = 'Makkah Health Cluster',
  title = 'Certificate of Appreciation',
  recipientName = '',
  bodyLine1 = 'This certifies that',
  bodyLine2 = 'has volunteered with dedication and made a valuable contribution to',
  bodyLine3 = 'Makkah Health Cluster',
  note = '',
  issuedDateStr = '',
  issuerName = '',
  certCode = '',
  signatureBuffer = null,
} = {}) {
  const PAGE_W = 842, PAGE_H = 595;
  const GREEN = [0 / 255, 105 / 255, 62 / 255];
  const GOLD = [201 / 255, 162 / 255, 39 / 255];
  const DARK = [0.11, 0.15, 0.14];
  const MUTED = [0.4, 0.44, 0.41];

  recipientName = certSanitize(recipientName) || 'Volunteer';
  title = certSanitize(title) || 'Certificate of Appreciation';
  note = certSanitize(note);
  issuerName = certSanitize(issuerName);

  // Best-effort signature image decode. Never blocks certificate generation if it fails.
  let sigImage = null;
  if (signatureBuffer && signatureBuffer.length > 4) {
    try {
      if (signatureBuffer[0] === 0xFF && signatureBuffer[1] === 0xD8) {
        const info = readJpegInfo(signatureBuffer);
        if (info) sigImage = { kind: 'jpeg', width: info.width, height: info.height, components: info.components || 3, jpegBuffer: signatureBuffer };
      } else if (signatureBuffer.readUInt32BE(0) === 0x89504e47) {
        const png = decodePNG(signatureBuffer);
        sigImage = { kind: 'png', width: png.width, height: png.height, rgbBuffer: png.rgb, alphaBuffer: png.alpha };
      }
    } catch (e) {
      sigImage = null;
    }
  }

  const ops = [];
  const setStroke = (c, w) => ops.push(`${c[0].toFixed(3)} ${c[1].toFixed(3)} ${c[2].toFixed(3)} RG`, `${w} w`);
  const setFill = (c) => ops.push(`${c[0].toFixed(3)} ${c[1].toFixed(3)} ${c[2].toFixed(3)} rg`);
  const rectStroke = (x, y, w, h) => ops.push(`${x} ${y} ${w} ${h} re`, 'S');

  function text(str, x, y, font, size, color, align = 'left') {
    str = certSanitize(str);
    const table = font === 'F1' ? HELV_BOLD_W : HELV_W;
    let drawX = x;
    if (align === 'center') drawX = x - certTextWidth(str, table, size) / 2;
    else if (align === 'right') drawX = x - certTextWidth(str, table, size);
    ops.push('BT', `${color[0].toFixed(3)} ${color[1].toFixed(3)} ${color[2].toFixed(3)} rg`, `/${font} ${size} Tf`, `${drawX.toFixed(2)} ${y} Td`, `(${certEscape(str)}) Tj`, 'ET');
  }

  setStroke(GREEN, 3);
  rectStroke(24, 24, PAGE_W - 48, PAGE_H - 48);
  setStroke(GOLD, 1.2);
  rectStroke(34, 34, PAGE_W - 68, PAGE_H - 68);

  const cx = PAGE_W / 2, cy = PAGE_H - 95, rOuter = 22, rInner = 9;
  setFill(GOLD);
  let starPath = '';
  for (let i = 0; i < 16; i++) {
    const angle = (Math.PI / 8) * i - Math.PI / 2;
    const r = i % 2 === 0 ? rOuter : rInner;
    const px = cx + r * Math.cos(angle);
    const py = cy + r * Math.sin(angle);
    starPath += `${px.toFixed(2)} ${py.toFixed(2)} ${i === 0 ? 'm' : 'l'}\n`;
  }
  ops.push(starPath.trim(), 'h', 'f');

  text(orgNameEn.toUpperCase(), PAGE_W / 2, PAGE_H - 140, 'F1', 15, GREEN, 'center');
  text(title, PAGE_W / 2, PAGE_H - 200, 'F1', 30, DARK, 'center');

  setStroke(GOLD, 1);
  ops.push(`${PAGE_W / 2 - 60} ${PAGE_H - 215} m`, `${PAGE_W / 2 + 60} ${PAGE_H - 215} l`, 'S');

  text(bodyLine1, PAGE_W / 2, PAGE_H - 255, 'F2', 14, MUTED, 'center');
  text(recipientName, PAGE_W / 2, PAGE_H - 295, 'F1', 26, GREEN, 'center');
  text(bodyLine2, PAGE_W / 2, PAGE_H - 335, 'F2', 14, MUTED, 'center');
  text(bodyLine3, PAGE_W / 2, PAGE_H - 358, 'F2', 14, MUTED, 'center');
  if (note) text(note, PAGE_W / 2, PAGE_H - 390, 'F2', 12.5, DARK, 'center');

  text(`Date: ${certSanitize(issuedDateStr)}`, 90, 90, 'F3', 11, DARK, 'left');
  setStroke(MUTED, 0.7);
  ops.push(`${PAGE_W - 300} 100 m`, `${PAGE_W - 90} 100 l`, 'S');

  if (sigImage) {
    const maxW = 150, maxH = 40;
    const scale = Math.min(maxW / sigImage.width, maxH / sigImage.height, 1);
    const drawW = sigImage.width * scale;
    const drawH = sigImage.height * scale;
    const drawX = (PAGE_W - 195) - drawW / 2;
    const drawY = 103;
    ops.push('q', `${drawW.toFixed(2)} 0 0 ${drawH.toFixed(2)} ${drawX.toFixed(2)} ${drawY.toFixed(2)} cm`, '/ImSig Do', 'Q');
  }

  text(issuerName || 'Program Manager', PAGE_W - 195, 82, 'F3', 11, DARK, 'center');
  text('Authorized Signature', PAGE_W - 195, 68, 'F3', 9, MUTED, 'center');
  if (certCode) text(`Certificate ID: ${certSanitize(certCode)}`, PAGE_W / 2, 45, 'F3', 9, MUTED, 'center');

  const contentBuf = Buffer.from(ops.join('\n'), 'latin1');

  // ---- Assemble PDF objects (binary-safe: raw Buffers throughout, no string round-trips) ----
  const imageObjNum = sigImage ? 8 : null;
  const smaskObjNum = sigImage && sigImage.kind === 'png' && sigImage.alphaBuffer ? 9 : null;
  const resourcesXObject = sigImage ? ` /XObject << /ImSig ${imageObjNum} 0 R >>` : '';

  const catalog = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
  const pagesObj = '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n';
  const pageObj = `3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 5 0 R /F2 6 0 R /F3 7 0 R >>${resourcesXObject} >> /Contents 4 0 R >>\nendobj\n`;
  const contentHeader = `4 0 obj\n<< /Length ${contentBuf.length} >>\nstream\n`;
  const contentFooter = '\nendstream\nendobj\n';
  const font1 = '5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n';
  const font2 = '6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>\nendobj\n';
  const font3 = '7 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n';

  const parts = [];
  const offsets = [0];
  let written = 0;
  function add(buf) { parts.push(buf); written += buf.length; }
  function addObj(str) { offsets.push(written); add(Buffer.from(str, 'latin1')); }

  add(Buffer.from('%PDF-1.4\n', 'latin1'));
  addObj(catalog);
  addObj(pagesObj);
  addObj(pageObj);
  offsets.push(written);
  add(Buffer.from(contentHeader, 'latin1'));
  add(contentBuf);
  add(Buffer.from(contentFooter, 'latin1'));
  addObj(font1);
  addObj(font2);
  addObj(font3);

  let totalObjects = 7;

  if (sigImage) {
    if (sigImage.kind === 'jpeg') {
      const colorSpace = sigImage.components === 1 ? '/DeviceGray' : '/DeviceRGB';
      offsets.push(written);
      add(Buffer.from(`${imageObjNum} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${sigImage.width} /Height ${sigImage.height} /ColorSpace ${colorSpace} /BitsPerComponent 8 /Filter /DCTDecode /Length ${sigImage.jpegBuffer.length} >>\nstream\n`, 'latin1'));
      add(sigImage.jpegBuffer);
      add(Buffer.from('\nendstream\nendobj\n', 'latin1'));
      totalObjects = imageObjNum;
    } else {
      const rgbDeflated = zlib.deflateSync(sigImage.rgbBuffer);
      const smaskRef = smaskObjNum ? ` /SMask ${smaskObjNum} 0 R` : '';
      offsets.push(written);
      add(Buffer.from(`${imageObjNum} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${sigImage.width} /Height ${sigImage.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode${smaskRef} /Length ${rgbDeflated.length} >>\nstream\n`, 'latin1'));
      add(rgbDeflated);
      add(Buffer.from('\nendstream\nendobj\n', 'latin1'));
      totalObjects = imageObjNum;
      if (smaskObjNum) {
        const alphaDeflated = zlib.deflateSync(sigImage.alphaBuffer);
        offsets.push(written);
        add(Buffer.from(`${smaskObjNum} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${sigImage.width} /Height ${sigImage.height} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length ${alphaDeflated.length} >>\nstream\n`, 'latin1'));
        add(alphaDeflated);
        add(Buffer.from('\nendstream\nendobj\n', 'latin1'));
        totalObjects = smaskObjNum;
      }
    }
  }

  const xrefStart = written;
  let xref = `xref\n0 ${totalObjects + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= totalObjects; i++) xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  xref += `trailer\n<< /Size ${totalObjects + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  add(Buffer.from(xref, 'latin1'));

  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// Database (SQLite via Node's built-in node:sqlite)
// ---------------------------------------------------------------------------
const db = new DatabaseSync(path.join(DATA_DIR, 'vms.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('vp','manager','volunteer')),
  manager_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS kpis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  target_value REAL,
  current_value REAL DEFAULT 0,
  unit TEXT,
  period TEXT,
  status TEXT NOT NULL DEFAULT 'on_track',
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ideas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submitted_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  response TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS complaints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submitted_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  resolution_notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  manager_id INTEGER NOT NULL,
  period TEXT,
  summary TEXT,
  status TEXT NOT NULL DEFAULT 'submitted',
  vp_notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uploaded_by INTEGER NOT NULL,
  filename TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  description TEXT,
  visible_to TEXT NOT NULL DEFAULT 'all',
  size INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS surveys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  google_form_url TEXT,
  google_sheet_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_by INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  volunteer_id INTEGER NOT NULL,
  issued_by INTEGER NOT NULL,
  title TEXT NOT NULL DEFAULT 'Certificate of Appreciation',
  note TEXT,
  cert_code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS hours_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  volunteer_id INTEGER NOT NULL,
  logged_by INTEGER NOT NULL,
  hours REAL NOT NULL,
  work_date TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS shifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  location TEXT,
  shift_date TEXT NOT NULL,
  start_time TEXT,
  end_time TEXT,
  notes TEXT,
  created_by INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS shift_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shift_id INTEGER NOT NULL,
  volunteer_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'assigned',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user INTEGER NOT NULL,
  to_user INTEGER NOT NULL,
  body TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// Safe migration: add newer profile columns to an existing 'users' table without wiping data.
const existingUserCols = db.prepare("PRAGMA table_info(users)").all().map((c) => c.name);
const newUserCols = {
  phone: 'TEXT',
  national_id: 'TEXT',
  department: 'TEXT',
  skills: 'TEXT',
  emergency_contact: 'TEXT',
  medical_clearance: 'TEXT',
  signature_data: 'TEXT',
};
for (const [col, type] of Object.entries(newUserCols)) {
  if (!existingUserCols.includes(col)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${col} ${type}`);
  }
}

const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const seedManagers = [
    { name: 'Mohammad Al Qarni', email: 'mohammad.alqarni@example.org', password: 'Qarni@2026' },
    { name: 'Abdullah Alwaheedy', email: 'abdullah.alwaheedy@example.org', password: 'Waheedy@2026' },
  ];
  const managerIds = seedManagers.map((m) => {
    const info = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)')
      .run(m.name, m.email, hashPassword(m.password), 'manager');
    return info.lastInsertRowid;
  });

  for (let i = 1; i <= 40; i++) {
    const vEmail = `volunteer${i}@example.org`;
    const vPassword = `Volunteer${i}@2026`;
    const managerId = managerIds[i <= 20 ? 0 : 1];
    db.prepare('INSERT INTO users (name, email, password, role, manager_id) VALUES (?,?,?,?,?)')
      .run(`Volunteer ${i}`, vEmail, hashPassword(vPassword), 'volunteer', managerId);
  }

  console.log('============================================');
  console.log(' First run: default accounts created');
  console.log(' Manager1: ' + seedManagers[0].email + ' / ' + seedManagers[0].password);
  console.log(' Manager2: ' + seedManagers[1].email + ' / ' + seedManagers[1].password);
  console.log(' + 40 volunteer accounts: volunteer1@example.org .. volunteer40@example.org');
  console.log(' (passwords follow the pattern Volunteer<N>@2026, e.g. Volunteer1@2026)');
  console.log(' There is no VP account in this setup. Please change these passwords after first login.');
  console.log('============================================');
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(body);
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    const MAX = 20 * 1024 * 1024;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX) { reject(new Error('Payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
function getAuthUser(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7);
  const payload = verifyToken(token);
  if (!payload) return null;
  const user = db.prepare('SELECT id, name, email, role, manager_id, active, signature_data FROM users WHERE id = ?').get(payload.id);
  if (!user || !user.active) return null;
  return user;
}
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, email: u.email, role: u.role, manager_id: u.manager_id, has_signature: !!u.signature_data };
}
function visibleUserIds(user) {
  if (user.role === 'vp') return db.prepare('SELECT id FROM users').all().map((r) => r.id);
  if (user.role === 'manager') {
    const team = db.prepare('SELECT id FROM users WHERE manager_id = ?').all(user.id).map((r) => r.id);
    return [user.id, ...team];
  }
  return [user.id];
}
function isManagerOf(user, targetId) {
  if (user.role === 'vp') return true;
  const row = db.prepare('SELECT manager_id FROM users WHERE id = ?').get(targetId);
  return row && row.manager_id === user.id;
}
function visibleKpiOwnerIds(user) {
  if (user.role === 'vp') return db.prepare('SELECT id FROM users').all().map((r) => r.id);
  if (user.role === 'manager') return [user.id];
  return user.manager_id ? [user.manager_id] : [];
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
const routes = [];
function route(method, pattern, handler) {
  const keys = [];
  const regex = new RegExp('^' + pattern.replace(/:[a-zA-Z]+/g, (m) => { keys.push(m.slice(1)); return '([^/]+)'; }) + '$');
  routes.push({ method, regex, keys, handler });
}

route('POST', '/api/login', async (req, res) => {
  const body = await readJsonBody(req);
  const { email, password } = body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase().trim());
  if (!user || !user.active || !verifyPassword(password || '', user.password)) {
    return send(res, 401, { error: 'Invalid email or password' });
  }
  const token = createToken({ id: user.id });
  send(res, 200, { token, user: publicUser(user) });
});

route('GET', '/api/me', async (req, res, ctx) => { send(res, 200, { user: publicUser(ctx.user) }); });

route('POST', '/api/me/password', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  const full = db.prepare('SELECT * FROM users WHERE id = ?').get(ctx.user.id);
  if (!verifyPassword(body.current_password || '', full.password)) {
    return send(res, 400, { error: 'Current password is incorrect' });
  }
  if (!body.new_password || body.new_password.length < 6) {
    return send(res, 400, { error: 'New password must be at least 6 characters' });
  }
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(body.new_password), ctx.user.id);
  send(res, 200, { ok: true });
});

route('POST', '/api/me/signature', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  if (!body.data_base64) return send(res, 400, { error: 'Image data required' });
  let buf;
  try { buf = Buffer.from(body.data_base64, 'base64'); } catch { return send(res, 400, { error: 'Invalid image data' }); }
  if (!buf.length) return send(res, 400, { error: 'Invalid image data' });
  if (buf.length > 400 * 1024) return send(res, 400, { error: 'Image is too large (max 400KB). Please upload a smaller image.' });
  const isJpeg = buf[0] === 0xFF && buf[1] === 0xD8;
  const isPng = buf.length > 4 && buf.readUInt32BE(0) === 0x89504e47;
  if (!isJpeg && !isPng) return send(res, 400, { error: 'Please upload a PNG or JPEG image.' });
  db.prepare('UPDATE users SET signature_data = ? WHERE id = ?').run(body.data_base64, ctx.user.id);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/me/signature', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  db.prepare('UPDATE users SET signature_data = NULL WHERE id = ?').run(ctx.user.id);
  send(res, 200, { ok: true });
});

const USER_COLS = 'id, name, email, role, manager_id, active, created_at, phone, national_id, department, skills, emergency_contact, medical_clearance';

route('GET', '/api/users', async (req, res, ctx) => {
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare(`SELECT ${USER_COLS} FROM users ORDER BY role, name`).all();
  } else if (ctx.user.role === 'manager') {
    rows = db.prepare(`SELECT ${USER_COLS} FROM users WHERE manager_id = ? OR id = ? ORDER BY name`).all(ctx.user.id, ctx.user.id);
  } else {
    rows = db.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).all(ctx.user.id);
  }
  send(res, 200, { users: rows });
});

route('GET', '/api/users/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, id) || ctx.user.id === id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const user = db.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).get(id);
  if (!user) return send(res, 404, { error: 'Not found' });
  send(res, 200, { user });
});

route('POST', '/api/users', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  const { name, email, password, role } = body;
  if (!name || !email || !password || !role) return send(res, 400, { error: 'Missing fields' });
  if (ctx.user.role === 'vp' && role !== 'manager') return send(res, 403, { error: 'VP can only create manager accounts here (managers add their own volunteers)' });
  if (ctx.user.role === 'manager' && role !== 'volunteer') return send(res, 403, { error: 'Managers can only add volunteers' });
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (exists) return send(res, 400, { error: 'A user with that email already exists' });
  const managerId = role === 'volunteer' ? ctx.user.id : null;
  const info = db.prepare('INSERT INTO users (name, email, password, role, manager_id) VALUES (?, ?, ?, ?, ?)')
    .run(name, email.toLowerCase().trim(), hashPassword(password), role, managerId);
  const user = db.prepare('SELECT id, name, email, role, manager_id, active FROM users WHERE id = ?').get(info.lastInsertRowid);
  send(res, 201, { user });
});

route('PUT', '/api/users/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, id) || ctx.user.id === id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (typeof body.name === 'string') { fields.push('name = ?'); values.push(body.name); }
  if (typeof body.active === 'boolean' && ctx.user.role !== 'volunteer') { fields.push('active = ?'); values.push(body.active ? 1 : 0); }
  if (body.password) { fields.push('password = ?'); values.push(hashPassword(body.password)); }
  if (ctx.user.role !== 'volunteer') {
    for (const f of ['phone', 'national_id', 'department', 'skills', 'emergency_contact', 'medical_clearance']) {
      if (typeof body[f] === 'string') { fields.push(`${f} = ?`); values.push(body[f]); }
    }
  }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  values.push(id);
  db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/users/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  if (!isManagerOf(ctx.user, id) && ctx.user.role !== 'vp') return send(res, 403, { error: 'Not permitted' });
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/kpis', async (req, res, ctx) => {
  const ids = visibleKpiOwnerIds(ctx.user);
  const placeholders = ids.map(() => '?').join(',') || '0';
  const rows = db.prepare(`SELECT k.*, u.name AS owner_name FROM kpis k JOIN users u ON u.id = k.owner_id WHERE k.owner_id IN (${placeholders}) ORDER BY k.created_at DESC`).all(...ids);
  send(res, 200, { kpis: rows });
});

route('POST', '/api/kpis', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const ownerId = ctx.user.role === 'vp' && body.owner_id ? Number(body.owner_id) : ctx.user.id;
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO kpis (owner_id, title, description, target_value, current_value, unit, period, status, created_by) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(ownerId, body.title, body.description || '', body.target_value ?? null, body.current_value ?? 0, body.unit || '', body.period || '', body.status || 'on_track', ctx.user.id);
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/kpis/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const kpi = db.prepare('SELECT * FROM kpis WHERE id = ?').get(id);
  if (!kpi) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || kpi.owner_id === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  for (const f of ['title', 'description', 'target_value', 'current_value', 'unit', 'period', 'status']) {
    if (body[f] !== undefined) { fields.push(`${f} = ?`); values.push(body[f]); }
  }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE kpis SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('DELETE', '/api/kpis/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const kpi = db.prepare('SELECT * FROM kpis WHERE id = ?').get(id);
  if (!kpi) return send(res, 404, { error: 'Not found' });
  if (ctx.user.role !== 'vp' && kpi.owner_id !== ctx.user.id) return send(res, 403, { error: 'Not permitted' });
  db.prepare('DELETE FROM kpis WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/ideas', async (req, res, ctx) => {
  const ids = visibleUserIds(ctx.user);
  const placeholders = ids.map(() => '?').join(',') || '0';
  const rows = db.prepare(`SELECT i.*, u.name AS submitter_name, u.role AS submitter_role FROM ideas i JOIN users u ON u.id = i.submitted_by WHERE i.submitted_by IN (${placeholders}) ORDER BY i.created_at DESC`).all(...ids);
  send(res, 200, { ideas: rows });
});

route('POST', '/api/ideas', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO ideas (submitted_by, title, description) VALUES (?,?,?)').run(ctx.user.id, body.title, body.description || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/ideas/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const idea = db.prepare('SELECT * FROM ideas WHERE id = ?').get(id);
  if (!idea) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, idea.submitted_by) || idea.submitted_by === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (body.status && ctx.user.role !== 'volunteer') { fields.push('status = ?'); values.push(body.status); }
  if (body.response !== undefined && ctx.user.role !== 'volunteer') { fields.push('response = ?'); values.push(body.response); }
  if (body.title && idea.submitted_by === ctx.user.id) { fields.push('title = ?'); values.push(body.title); }
  if (body.description !== undefined && idea.submitted_by === ctx.user.id) { fields.push('description = ?'); values.push(body.description); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE ideas SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('GET', '/api/complaints', async (req, res, ctx) => {
  const ids = visibleUserIds(ctx.user);
  const placeholders = ids.map(() => '?').join(',') || '0';
  const rows = db.prepare(`SELECT c.*, u.name AS submitter_name, u.role AS submitter_role FROM complaints c JOIN users u ON u.id = c.submitted_by WHERE c.submitted_by IN (${placeholders}) ORDER BY c.created_at DESC`).all(...ids);
  send(res, 200, { complaints: rows });
});

route('POST', '/api/complaints', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO complaints (submitted_by, title, description) VALUES (?,?,?)').run(ctx.user.id, body.title, body.description || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/complaints/:id', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const c = db.prepare('SELECT * FROM complaints WHERE id = ?').get(id);
  if (!c) return send(res, 404, { error: 'Not found' });
  const allowed = ctx.user.role === 'vp' || isManagerOf(ctx.user, c.submitted_by) || c.submitted_by === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (body.status && ctx.user.role !== 'volunteer') { fields.push('status = ?'); values.push(body.status); }
  if (body.resolution_notes !== undefined && ctx.user.role !== 'volunteer') { fields.push('resolution_notes = ?'); values.push(body.resolution_notes); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE complaints SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('GET', '/api/reports', async (req, res, ctx) => {
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT r.*, u.name AS manager_name FROM reports r JOIN users u ON u.id = r.manager_id ORDER BY r.created_at DESC').all();
  } else if (ctx.user.role === 'manager') {
    rows = db.prepare('SELECT r.*, u.name AS manager_name FROM reports r JOIN users u ON u.id = r.manager_id WHERE r.manager_id = ? ORDER BY r.created_at DESC').all(ctx.user.id);
  } else {
    return send(res, 403, { error: 'Not permitted' });
  }
  send(res, 200, { reports: rows });
});

route('POST', '/api/reports', async (req, res, ctx) => {
  if (ctx.user.role !== 'manager') return send(res, 403, { error: 'Only managers submit reports to the VP' });
  const body = await readJsonBody(req);
  if (!body.summary) return send(res, 400, { error: 'Summary required' });
  const info = db.prepare('INSERT INTO reports (manager_id, period, summary) VALUES (?,?,?)').run(ctx.user.id, body.period || '', body.summary);
  send(res, 201, { id: info.lastInsertRowid });
});

route('PUT', '/api/reports/:id', async (req, res, ctx) => {
  if (ctx.user.role !== 'vp') return send(res, 403, { error: 'Only the VP can update report status' });
  const id = Number(ctx.params.id);
  const body = await readJsonBody(req);
  const fields = []; const values = [];
  if (body.status) { fields.push('status = ?'); values.push(body.status); }
  if (body.vp_notes !== undefined) { fields.push('vp_notes = ?'); values.push(body.vp_notes); }
  if (!fields.length) return send(res, 400, { error: 'Nothing to update' });
  values.push(id);
  db.prepare(`UPDATE reports SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  send(res, 200, { ok: true });
});

route('GET', '/api/reports/snapshot', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const scope = visibleUserIds(ctx.user);
  const placeholders = scope.map(() => '?').join(',') || '0';
  const openComplaints = db.prepare(`SELECT COUNT(*) c FROM complaints WHERE status != 'resolved' AND submitted_by IN (${placeholders})`).get(...scope).c;
  const newIdeas = db.prepare(`SELECT COUNT(*) c FROM ideas WHERE status = 'new' AND submitted_by IN (${placeholders})`).get(...scope).c;
  const kpiCount = db.prepare(`SELECT COUNT(*) c FROM kpis WHERE owner_id IN (${placeholders})`).get(...scope).c;
  send(res, 200, { openComplaints, newIdeas, kpiCount });
});

route('GET', '/api/files', async (req, res, ctx) => {
  const rows = db.prepare('SELECT f.id, f.filename, f.description, f.visible_to, f.size, f.created_at, u.name AS uploader_name FROM files f JOIN users u ON u.id = f.uploaded_by ORDER BY f.created_at DESC').all();
  send(res, 200, { files: rows });
});

route('POST', '/api/files', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Only managers/VP can upload files' });
  const body = await readJsonBody(req);
  const { filename, description, data_base64, visible_to } = body;
  if (!filename || !data_base64) return send(res, 400, { error: 'filename and data_base64 required' });
  const safeExt = path.extname(filename).toLowerCase();
  if (!['.csv', '.xlsx', '.xls', '.tsv'].includes(safeExt)) return send(res, 400, { error: 'Only .csv, .tsv, .xls, .xlsx files are allowed' });
  const storedName = crypto.randomBytes(16).toString('hex') + safeExt;
  const buffer = Buffer.from(data_base64, 'base64');
  fs.writeFileSync(path.join(UPLOAD_DIR, storedName), buffer);
  const info = db.prepare('INSERT INTO files (uploaded_by, filename, stored_name, description, visible_to, size) VALUES (?,?,?,?,?,?)')
    .run(ctx.user.id, filename, storedName, description || '', visible_to || 'all', buffer.length);
  send(res, 201, { id: info.lastInsertRowid });
});

route('GET', '/api/files/:id/download', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(id);
  if (!file) return send(res, 404, { error: 'Not found' });
  const filePath = path.join(UPLOAD_DIR, file.stored_name);
  if (!fs.existsSync(filePath)) return send(res, 404, { error: 'File missing on disk' });
  const data = fs.readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${file.filename.replace(/"/g, '')}"` });
  res.end(data);
});

route('DELETE', '/api/files/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const id = Number(ctx.params.id);
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(id);
  if (!file) return send(res, 404, { error: 'Not found' });
  try { fs.unlinkSync(path.join(UPLOAD_DIR, file.stored_name)); } catch {}
  db.prepare('DELETE FROM files WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/surveys', async (req, res, ctx) => {
  const rows = db.prepare('SELECT s.*, u.name AS creator_name FROM surveys s JOIN users u ON u.id = s.created_by ORDER BY s.created_at DESC').all();
  send(res, 200, { surveys: rows });
});

route('POST', '/api/surveys', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO surveys (created_by, title, google_form_url, google_sheet_url) VALUES (?,?,?,?)').run(ctx.user.id, body.title, body.google_form_url || '', body.google_sheet_url || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('DELETE', '/api/surveys/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  db.prepare('DELETE FROM surveys WHERE id = ?').run(Number(ctx.params.id));
  send(res, 200, { ok: true });
});

route('GET', '/api/announcements', async (req, res, ctx) => {
  const rows = db.prepare('SELECT a.*, u.name AS creator_name FROM announcements a JOIN users u ON u.id = a.created_by ORDER BY a.created_at DESC LIMIT 50').all();
  send(res, 200, { announcements: rows });
});

route('POST', '/api/announcements', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  if (!body.title) return send(res, 400, { error: 'Title required' });
  const info = db.prepare('INSERT INTO announcements (created_by, title, body) VALUES (?,?,?)').run(ctx.user.id, body.title, body.body || '');
  send(res, 201, { id: info.lastInsertRowid });
});

// ---- CERTIFICATES ----
route('GET', '/api/certificates', async (req, res, ctx) => {
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT c.*, v.name AS volunteer_name, i.name AS issuer_name FROM certificates c JOIN users v ON v.id = c.volunteer_id JOIN users i ON i.id = c.issued_by ORDER BY c.created_at DESC').all();
  } else if (ctx.user.role === 'manager') {
    rows = db.prepare('SELECT c.*, v.name AS volunteer_name, i.name AS issuer_name FROM certificates c JOIN users v ON v.id = c.volunteer_id JOIN users i ON i.id = c.issued_by WHERE v.manager_id = ? ORDER BY c.created_at DESC').all(ctx.user.id);
  } else {
    rows = db.prepare('SELECT c.*, v.name AS volunteer_name, i.name AS issuer_name FROM certificates c JOIN users v ON v.id = c.volunteer_id JOIN users i ON i.id = c.issued_by WHERE c.volunteer_id = ? ORDER BY c.created_at DESC').all(ctx.user.id);
  }
  send(res, 200, { certificates: rows });
});

route('POST', '/api/certificates', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const volunteerId = Number(body.volunteer_id);
  if (!volunteerId) return send(res, 400, { error: 'volunteer_id required' });
  const volunteer = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'volunteer'").get(volunteerId);
  if (!volunteer) return send(res, 404, { error: 'Volunteer not found' });
  if (ctx.user.role === 'manager' && volunteer.manager_id !== ctx.user.id) return send(res, 403, { error: 'Not your volunteer' });
  const certCode = 'MHC-' + new Date().getFullYear() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const info = db.prepare('INSERT INTO certificates (volunteer_id, issued_by, title, note, cert_code) VALUES (?,?,?,?,?)')
    .run(volunteerId, ctx.user.id, body.title || 'Certificate of Appreciation', body.note || '', certCode);
  send(res, 201, { id: info.lastInsertRowid, cert_code: certCode });
});

route('GET', '/api/certificates/:id/download', async (req, res, ctx) => {
  const id = Number(ctx.params.id);
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id);
  if (!cert) return send(res, 404, { error: 'Not found' });
  const volunteer = db.prepare('SELECT * FROM users WHERE id = ?').get(cert.volunteer_id);
  const allowed = ctx.user.role === 'vp' || (ctx.user.role === 'manager' && volunteer && volunteer.manager_id === ctx.user.id) || cert.volunteer_id === ctx.user.id;
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const issuer = db.prepare('SELECT * FROM users WHERE id = ?').get(cert.issued_by);
  const issuedDate = cert.created_at ? cert.created_at.split(' ')[0] : '';
  let signatureBuffer = null;
  if (issuer && issuer.signature_data) {
    try { signatureBuffer = Buffer.from(issuer.signature_data, 'base64'); } catch { signatureBuffer = null; }
  }
  const pdfBuffer = buildCertificatePDF({
    recipientName: volunteer ? volunteer.name : 'Volunteer',
    title: cert.title,
    note: cert.note,
    issuedDateStr: issuedDate,
    issuerName: issuer ? issuer.name : '',
    certCode: cert.cert_code,
    signatureBuffer,
  });
  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'Content-Disposition': `attachment; filename="certificate-${cert.cert_code}.pdf"`,
  });
  res.end(pdfBuffer);
});

route('DELETE', '/api/certificates/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const id = Number(ctx.params.id);
  const cert = db.prepare('SELECT * FROM certificates WHERE id = ?').get(id);
  if (!cert) return send(res, 404, { error: 'Not found' });
  if (ctx.user.role === 'manager') {
    const volunteer = db.prepare('SELECT * FROM users WHERE id = ?').get(cert.volunteer_id);
    if (!volunteer || volunteer.manager_id !== ctx.user.id) return send(res, 403, { error: 'Not permitted' });
  }
  db.prepare('DELETE FROM certificates WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

// ---- HOURS / ATTENDANCE ----
route('GET', '/api/hours', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT h.*, v.name AS volunteer_name FROM hours_logs h JOIN users v ON v.id = h.volunteer_id ORDER BY h.work_date DESC, h.created_at DESC').all();
  } else {
    rows = db.prepare('SELECT h.*, v.name AS volunteer_name FROM hours_logs h JOIN users v ON v.id = h.volunteer_id WHERE v.manager_id = ? ORDER BY h.work_date DESC, h.created_at DESC').all(ctx.user.id);
  }
  send(res, 200, { hours: rows });
});

route('POST', '/api/hours', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  const volunteerId = Number(body.volunteer_id);
  const hours = Number(body.hours);
  if (!volunteerId || !hours || !body.work_date) return send(res, 400, { error: 'volunteer_id, hours and work_date required' });
  const volunteer = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'volunteer'").get(volunteerId);
  if (!volunteer) return send(res, 404, { error: 'Volunteer not found' });
  if (ctx.user.role === 'manager' && volunteer.manager_id !== ctx.user.id) return send(res, 403, { error: 'Not your volunteer' });
  const info = db.prepare('INSERT INTO hours_logs (volunteer_id, logged_by, hours, work_date, note) VALUES (?,?,?,?,?)')
    .run(volunteerId, ctx.user.id, hours, body.work_date, body.note || '');
  send(res, 201, { id: info.lastInsertRowid });
});

route('DELETE', '/api/hours/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const id = Number(ctx.params.id);
  const log = db.prepare('SELECT * FROM hours_logs WHERE id = ?').get(id);
  if (!log) return send(res, 404, { error: 'Not found' });
  if (ctx.user.role === 'manager') {
    const volunteer = db.prepare('SELECT * FROM users WHERE id = ?').get(log.volunteer_id);
    if (!volunteer || volunteer.manager_id !== ctx.user.id) return send(res, 403, { error: 'Not permitted' });
  }
  db.prepare('DELETE FROM hours_logs WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('GET', '/api/hours/export', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT h.work_date, v.name AS volunteer_name, v.national_id, h.hours, h.note FROM hours_logs h JOIN users v ON v.id = h.volunteer_id ORDER BY h.work_date DESC').all();
  } else {
    rows = db.prepare('SELECT h.work_date, v.name AS volunteer_name, v.national_id, h.hours, h.note FROM hours_logs h JOIN users v ON v.id = h.volunteer_id WHERE v.manager_id = ? ORDER BY h.work_date DESC').all(ctx.user.id);
  }
  const csvEscape = (s) => `"${String(s == null ? '' : s).replace(/"/g, '""')}"`;
  const header = ['Date', 'Volunteer', 'National ID', 'Hours', 'Note'].join(',');
  const lines = rows.map((r) => [csvEscape(r.work_date), csvEscape(r.volunteer_name), csvEscape(r.national_id), csvEscape(r.hours), csvEscape(r.note)].join(','));
  const csv = '﻿' + [header, ...lines].join('\r\n');
  res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="volunteer-hours.csv"' });
  res.end(csv);
});

// ---- SHIFTS / SCHEDULING ----
route('GET', '/api/shifts', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare('SELECT * FROM shifts ORDER BY shift_date DESC').all();
  } else {
    rows = db.prepare('SELECT * FROM shifts WHERE created_by = ? ORDER BY shift_date DESC').all(ctx.user.id);
  }
  const shiftIds = rows.map((r) => r.id);
  const placeholders = shiftIds.map(() => '?').join(',') || '0';
  const assignments = shiftIds.length
    ? db.prepare(`SELECT a.*, v.name AS volunteer_name FROM shift_assignments a JOIN users v ON v.id = a.volunteer_id WHERE a.shift_id IN (${placeholders})`).all(...shiftIds)
    : [];
  const byShift = {};
  for (const a of assignments) { (byShift[a.shift_id] ||= []).push(a); }
  for (const s of rows) s.assignments = byShift[s.id] || [];
  send(res, 200, { shifts: rows });
});

route('POST', '/api/shifts', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const body = await readJsonBody(req);
  if (!body.title || !body.shift_date) return send(res, 400, { error: 'title and shift_date required' });
  const info = db.prepare('INSERT INTO shifts (title, location, shift_date, start_time, end_time, notes, created_by) VALUES (?,?,?,?,?,?,?)')
    .run(body.title, body.location || '', body.shift_date, body.start_time || '', body.end_time || '', body.notes || '', ctx.user.id);
  send(res, 201, { id: info.lastInsertRowid });
});

route('DELETE', '/api/shifts/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const id = Number(ctx.params.id);
  const shift = db.prepare('SELECT * FROM shifts WHERE id = ?').get(id);
  if (!shift) return send(res, 404, { error: 'Not found' });
  if (ctx.user.role !== 'vp' && shift.created_by !== ctx.user.id) return send(res, 403, { error: 'Not permitted' });
  db.prepare('DELETE FROM shift_assignments WHERE shift_id = ?').run(id);
  db.prepare('DELETE FROM shifts WHERE id = ?').run(id);
  send(res, 200, { ok: true });
});

route('POST', '/api/shifts/:id/assignments', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  const shiftId = Number(ctx.params.id);
  const shift = db.prepare('SELECT * FROM shifts WHERE id = ?').get(shiftId);
  if (!shift) return send(res, 404, { error: 'Not found' });
  const body = await readJsonBody(req);
  const volunteerId = Number(body.volunteer_id);
  const volunteer = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'volunteer'").get(volunteerId);
  if (!volunteer) return send(res, 404, { error: 'Volunteer not found' });
  if (ctx.user.role === 'manager' && volunteer.manager_id !== ctx.user.id) return send(res, 403, { error: 'Not your volunteer' });
  const info = db.prepare('INSERT INTO shift_assignments (shift_id, volunteer_id) VALUES (?,?)').run(shiftId, volunteerId);
  send(res, 201, { id: info.lastInsertRowid });
});

route('DELETE', '/api/shift-assignments/:id', async (req, res, ctx) => {
  if (ctx.user.role === 'volunteer') return send(res, 403, { error: 'Not permitted' });
  db.prepare('DELETE FROM shift_assignments WHERE id = ?').run(Number(ctx.params.id));
  send(res, 200, { ok: true });
});

// ---- MESSAGES (1-to-1) ----
route('GET', '/api/messages/contacts', async (req, res, ctx) => {
  let rows;
  if (ctx.user.role === 'vp') {
    rows = db.prepare("SELECT id, name, role FROM users WHERE id != ? AND active = 1 ORDER BY role, name").all(ctx.user.id);
  } else if (ctx.user.role === 'manager') {
    rows = db.prepare("SELECT id, name, role FROM users WHERE manager_id = ? AND active = 1 ORDER BY name").all(ctx.user.id);
  } else {
    rows = ctx.user.manager_id
      ? db.prepare("SELECT id, name, role FROM users WHERE id = ? AND active = 1").all(ctx.user.manager_id)
      : [];
  }
  send(res, 200, { contacts: rows });
});

route('GET', '/api/messages/with/:userId', async (req, res, ctx) => {
  const otherId = Number(ctx.params.userId);
  const other = db.prepare('SELECT * FROM users WHERE id = ?').get(otherId);
  if (!other) return send(res, 404, { error: 'Not found' });
  const allowed =
    ctx.user.role === 'vp' ||
    (ctx.user.role === 'manager' && other.manager_id === ctx.user.id) ||
    (ctx.user.role === 'volunteer' && ctx.user.manager_id === otherId);
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  const rows = db
    .prepare('SELECT * FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY created_at ASC')
    .all(ctx.user.id, otherId, otherId, ctx.user.id);
  db.prepare("UPDATE messages SET read_at = datetime('now') WHERE to_user = ? AND from_user = ? AND read_at IS NULL").run(ctx.user.id, otherId);
  send(res, 200, { messages: rows });
});

route('POST', '/api/messages', async (req, res, ctx) => {
  const body = await readJsonBody(req);
  const toUser = Number(body.to_user);
  const other = db.prepare('SELECT * FROM users WHERE id = ?').get(toUser);
  if (!other) return send(res, 404, { error: 'Not found' });
  const allowed =
    ctx.user.role === 'vp' ||
    (ctx.user.role === 'manager' && other.manager_id === ctx.user.id) ||
    (ctx.user.role === 'volunteer' && ctx.user.manager_id === toUser);
  if (!allowed) return send(res, 403, { error: 'Not permitted' });
  if (!body.body || !body.body.trim()) return send(res, 400, { error: 'Message body required' });
  const info = db.prepare('INSERT INTO messages (from_user, to_user, body) VALUES (?,?,?)').run(ctx.user.id, toUser, body.body.trim());
  send(res, 201, { id: info.lastInsertRowid });
});

route('GET', '/api/messages/unread-count', async (req, res, ctx) => {
  const c = db.prepare('SELECT COUNT(*) c FROM messages WHERE to_user = ? AND read_at IS NULL').get(ctx.user.id).c;
  send(res, 200, { count: c });
});

// ---------------------------------------------------------------------------
// Frontend, embedded as base64 (no separate files needed).
// ---------------------------------------------------------------------------
const INDEX_HTML = Buffer.from('PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04IiAvPgo8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCIgLz4KPHRpdGxlPk1ha2thaCBIZWFsdGggQ2x1c3RlciB8IFZvbHVudGVlciBNYW5hZ2VtZW50IFBvcnRhbDwvdGl0bGU+CjxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iL2Nzcy9zdHlsZS5jc3MiIC8+CjxzY3JpcHQgc3JjPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy94bHN4LzAuMTguNS94bHN4LmZ1bGwubWluLmpzIj48L3NjcmlwdD4KPC9oZWFkPgo8Ym9keT4KCjwhLS0gTE9HSU4gU0NSRUVOIC0tPgo8ZGl2IGlkPSJsb2dpblNjcmVlbiIgY2xhc3M9ImxvZ2luLXdyYXAiPgogIDxkaXYgY2xhc3M9ImxvZ2luLXBhdHRlcm4iPjwvZGl2PgogIDxkaXYgY2xhc3M9ImxvZ2luLWNhcmQiPgogICAgPGRpdiBjbGFzcz0ibG9naW4tbWFyayI+CiAgICAgIDxzdmcgdmlld0JveD0iMCAwIDEwMCAxMDAiIHdpZHRoPSI0NiIgaGVpZ2h0PSI0NiIgYXJpYS1oaWRkZW49InRydWUiPgogICAgICAgIDxwb2x5Z29uIHBvaW50cz0iNTAsNCA2MSwzNSA5NCwzNSA2Nyw1NSA3OCw4OCA1MCw2OCAyMiw4OCAzMyw1NSA2LDM1IDM5LDM1IgogICAgICAgICAgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ2YXIoLS1hY2NlbnQpIiBzdHJva2Utd2lkdGg9IjQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KICAgICAgPC9zdmc+CiAgICA8L2Rpdj4KICAgIDxoMT5NYWtrYWggSGVhbHRoIENsdXN0ZXI8L2gxPgogICAgPHAgY2xhc3M9ImFyLXN1YnRpdGxlIj7Yqtis2YXYuSDZhdmD2Kkg2KfZhNmF2YPYsdmF2Kkg2KfZhNi12K3ZijwvcD4KICAgIDxwIGNsYXNzPSJtdXRlZCI+Vm9sdW50ZWVyIE1hbmFnZW1lbnQgUG9ydGFsICZtZGFzaDsgU2lnbiBpbiB0byBjb250aW51ZTwvcD4KICAgIDxkaXYgY2xhc3M9ImxvZ2luLXRhYnMiPgogICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImxvZ2luLXRhYiBhY3RpdmUiIGlkPSJ0YWJNYW5hZ2VyIiBkYXRhLXJvbGU9Im1hbmFnZXIiPk1hbmFnZXIgTG9naW48L2J1dHRvbj4KICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJsb2dpbi10YWIiIGlkPSJ0YWJWb2x1bnRlZXIiIGRhdGEtcm9sZT0idm9sdW50ZWVyIj5Wb2x1bnRlZXIgTG9naW48L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGZvcm0gaWQ9ImxvZ2luRm9ybSI+CiAgICAgIDxsYWJlbD5FbWFpbDwvbGFiZWw+CiAgICAgIDxpbnB1dCB0eXBlPSJlbWFpbCIgaWQ9ImxvZ2luRW1haWwiIHJlcXVpcmVkIGF1dG9jb21wbGV0ZT0idXNlcm5hbWUiIC8+CiAgICAgIDxsYWJlbD5QYXNzd29yZDwvbGFiZWw+CiAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9ImxvZ2luUGFzc3dvcmQiIHJlcXVpcmVkIGF1dG9jb21wbGV0ZT0iY3VycmVudC1wYXNzd29yZCIgLz4KICAgICAgPGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXByaW1hcnkgYnRuLWJsb2NrIj5TaWduIEluPC9idXR0b24+CiAgICAgIDxwIGlkPSJsb2dpbkVycm9yIiBjbGFzcz0iZXJyb3ItdGV4dCI+PC9wPgogICAgPC9mb3JtPgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gQVBQIFNIRUxMIC0tPgo8ZGl2IGlkPSJhcHAiIGNsYXNzPSJhcHAgaGlkZGVuIj4KICA8YXNpZGUgY2xhc3M9InNpZGViYXIiPgogICAgPGRpdiBjbGFzcz0iYnJhbmQiPgogICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAxMDAgMTAwIiB3aWR0aD0iMjYiIGhlaWdodD0iMjYiIGFyaWEtaGlkZGVuPSJ0cnVlIj4KICAgICAgICA8cG9seWdvbiBwb2ludHM9IjUwLDQgNjEsMzUgOTQsMzUgNjcsNTUgNzgsODggNTAsNjggMjIsODggMzMsNTUgNiwzNSAzOSwzNSIKICAgICAgICAgIGZpbGw9Im5vbmUiIHN0cm9rZT0idmFyKC0tYWNjZW50KSIgc3Ryb2tlLXdpZHRoPSI1IiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+CiAgICAgIDwvc3ZnPgogICAgICA8c3Bhbj4KICAgICAgICA8ZGl2IGNsYXNzPSJicmFuZC1lbiI+TWFra2FoIEhlYWx0aCBDbHVzdGVyPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iYnJhbmQtYXIiPtiq2KzZhdi5INmF2YPYqSDYp9mE2YXZg9ix2YXYqSDYp9mE2LXYrdmKPC9kaXY+CiAgICAgIDwvc3Bhbj4KICAgIDwvZGl2PgogICAgPG5hdiBpZD0ibmF2TGlua3MiPjwvbmF2PgogICAgPGRpdiBjbGFzcz0ic2lkZWJhci1mb290ZXIiPgogICAgICA8ZGl2IGlkPSJ1c2VyQmFkZ2UiIGNsYXNzPSJ1c2VyLWJhZGdlIj48L2Rpdj4KICAgICAgPGJ1dHRvbiBpZD0iZWRpdE5hbWVCdG4iIGNsYXNzPSJidG4gYnRuLWdob3N0IGJ0bi1ibG9jayI+RWRpdCBteSBuYW1lPC9idXR0b24+CiAgICAgIDxidXR0b24gaWQ9Im15U2lnbmF0dXJlQnRuIiBjbGFzcz0iYnRuIGJ0bi1naG9zdCBidG4tYmxvY2sgaGlkZGVuIj5NeSBzaWduYXR1cmU8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBpZD0iY2hhbmdlUHdCdG4iIGNsYXNzPSJidG4gYnRuLWdob3N0IGJ0bi1ibG9jayI+Q2hhbmdlIHBhc3N3b3JkPC9idXR0b24+CiAgICAgIDxidXR0b24gaWQ9ImxvZ291dEJ0biIgY2xhc3M9ImJ0biBidG4tZ2hvc3QgYnRuLWJsb2NrIj5Mb2cgb3V0PC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2FzaWRlPgoKICA8bWFpbiBjbGFzcz0ibWFpbiI+CiAgICA8aGVhZGVyIGNsYXNzPSJ0b3BiYXIiPgogICAgICA8aDIgaWQ9InBhZ2VUaXRsZSI+RGFzaGJvYXJkPC9oMj4KICAgICAgPGRpdiBjbGFzcz0idG9wYmFyLXN1YiBtdXRlZCI+Vm9sdW50ZWVyIE1hbmFnZW1lbnQgUG9ydGFsPC9kaXY+CiAgICA8L2hlYWRlcj4KICAgIDxkaXYgaWQ9InZpZXciIGNsYXNzPSJ2aWV3Ij48L2Rpdj4KICA8L21haW4+CjwvZGl2PgoKPCEtLSBHZW5lcmljIG1vZGFsIC0tPgo8ZGl2IGlkPSJtb2RhbE92ZXJsYXkiIGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiI+CiAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwtaGVhZGVyIj4KICAgICAgPGgzIGlkPSJtb2RhbFRpdGxlIj5UaXRsZTwvaDM+CiAgICAgIDxidXR0b24gaWQ9Im1vZGFsQ2xvc2UiIGNsYXNzPSJidG4taWNvbiI+JnRpbWVzOzwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGlkPSJtb2RhbEJvZHkiIGNsYXNzPSJtb2RhbC1ib2R5Ij48L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8ZGl2IGlkPSJ0b2FzdCIgY2xhc3M9InRvYXN0IGhpZGRlbiI+PC9kaXY+Cgo8c2NyaXB0IHNyYz0iL2pzL2FwcC5qcyI+PC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=', 'base64').toString('utf8');
const STYLE_CSS = Buffer.from('OnJvb3QgewogIC8qIE1ha2thaCBIZWFsdGggQ2x1c3RlciB0aGVtZTogU2F1ZGkgZmxhZyBncmVlbiArIEthYWJhLWdvbGQgYWNjZW50ICovCiAgLS1wcmltYXJ5OiAjMDA2OTNlOwogIC0tcHJpbWFyeS1kYXJrOiAjMDAzZDI0OwogIC0tYWNjZW50OiAjYzlhMjI3OwogIC0tYmc6ICNmNWY3ZjU7CiAgLS1jYXJkOiAjZmZmZmZmOwogIC0tdGV4dDogIzFjMjYyMjsKICAtLW11dGVkOiAjNjY3MDY5OwogIC0tYm9yZGVyOiAjZTBlNmUxOwogIC0tZGFuZ2VyOiAjYjM0NjJjOwogIC0tc3VjY2VzczogIzAwNjkzZTsKICAtLXdhcm5pbmc6ICNjOWEyMjc7CiAgLS1yYWRpdXM6IDEwcHg7Cn0KCiogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CmJvZHkgewogIG1hcmdpbjogMDsKICBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAiU2Vnb2UgVUkiLCBSb2JvdG8sIEhlbHZldGljYSwgQXJpYWwsIHNhbnMtc2VyaWY7CiAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogIGNvbG9yOiB2YXIoLS10ZXh0KTsKfQouaGlkZGVuIHsgZGlzcGxheTogbm9uZSAhaW1wb3J0YW50OyB9Ci5tdXRlZCB7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IH0KCi8qIExvZ2luICovCi5sb2dpbi13cmFwIHsKICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgbWluLWhlaWdodDogMTAwdmg7CiAgZGlzcGxheTogZmxleDsKICBhbGlnbi1pdGVtczogY2VudGVyOwogIGp1c3RpZnktY29udGVudDogY2VudGVyOwogIGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCgxMzVkZWcsIHZhcigtLXByaW1hcnkpIDAlLCB2YXIoLS1wcmltYXJ5LWRhcmspIDEwMCUpOwogIG92ZXJmbG93OiBoaWRkZW47Cn0KLmxvZ2luLXBhdHRlcm4gewogIHBvc2l0aW9uOiBhYnNvbHV0ZTsgaW5zZXQ6IDA7CiAgb3BhY2l0eTogMC4xMDsKICBiYWNrZ3JvdW5kLWltYWdlOgogICAgcmFkaWFsLWdyYWRpZW50KGNpcmNsZSBhdCAyMCUgMjAlLCB0cmFuc3BhcmVudCAwIDE4cHgsIHJnYmEoMjU1LDI1NSwyNTUsMC41KSAxOXB4LCB0cmFuc3BhcmVudCAyMHB4KSwKICAgIHJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoNDVkZWcsIHJnYmEoMjU1LDI1NSwyNTUsMC4xNSkgMCAycHgsIHRyYW5zcGFyZW50IDJweCA0MHB4KSwKICAgIHJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoLTQ1ZGVnLCByZ2JhKDI1NSwyNTUsMjU1LDAuMTUpIDAgMnB4LCB0cmFuc3BhcmVudCAycHggNDBweCk7CiAgcG9pbnRlci1ldmVudHM6IG5vbmU7Cn0KLmxvZ2luLWNhcmQgewogIHBvc2l0aW9uOiByZWxhdGl2ZTsKICBiYWNrZ3JvdW5kOiB2YXIoLS1jYXJkKTsKICBwYWRkaW5nOiA0MHB4OwogIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgd2lkdGg6IDM2MHB4OwogIG1heC13aWR0aDogOTJ2dzsKICBib3gtc2hhZG93OiAwIDIwcHggNTBweCByZ2JhKDAsMCwwLDAuMyk7CiAgdGV4dC1hbGlnbjogY2VudGVyOwogIGJvcmRlci10b3A6IDRweCBzb2xpZCB2YXIoLS1hY2NlbnQpOwp9Ci5sb2dpbi1tYXJrIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBjZW50ZXI7IG1hcmdpbi1ib3R0b206IDEycHg7IH0KLmxvZ2luLWNhcmQgaDEgeyBmb250LXNpemU6IDIwcHg7IG1hcmdpbjogMCAwIDJweDsgY29sb3I6IHZhcigtLXByaW1hcnktZGFyayk7IH0KLmFyLXN1YnRpdGxlIHsgbWFyZ2luOiAwIDAgMTBweDsgZm9udC1zaXplOiAxNXB4OyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBkaXJlY3Rpb246IHJ0bDsgfQoubG9naW4tY2FyZCBwIHsgbWFyZ2luLXRvcDogMDsgbWFyZ2luLWJvdHRvbTogMjBweDsgfQoubG9naW4tY2FyZCBsYWJlbCB7IGRpc3BsYXk6IGJsb2NrOyBmb250LXNpemU6IDEzcHg7IG1hcmdpbjogMTRweCAwIDZweDsgZm9udC13ZWlnaHQ6IDYwMDsgdGV4dC1hbGlnbjogbGVmdDsgfQoubG9naW4tY2FyZCBpbnB1dCB7IHdpZHRoOiAxMDAlOyBwYWRkaW5nOiAxMHB4IDEycHg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDhweDsgZm9udC1zaXplOiAxNHB4OyB9Ci5lcnJvci10ZXh0IHsgY29sb3I6IHZhcigtLWRhbmdlcik7IGZvbnQtc2l6ZTogMTNweDsgbWluLWhlaWdodDogMThweDsgbWFyZ2luLXRvcDogMTBweDsgfQoubG9naW4tdGFicyB7IGRpc3BsYXk6IGZsZXg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDhweDsgb3ZlcmZsb3c6IGhpZGRlbjsgbWFyZ2luLWJvdHRvbTogNHB4OyB9Ci5sb2dpbi10YWIgeyBmbGV4OiAxOyBwYWRkaW5nOiAxMHB4IDhweDsgYm9yZGVyOiBub25lOyBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGZvbnQtc2l6ZTogMTNweDsgZm9udC13ZWlnaHQ6IDcwMDsgY3Vyc29yOiBwb2ludGVyOyB9Ci5sb2dpbi10YWIuYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeSk7IGNvbG9yOiAjZmZmOyB9CgovKiBTaWduYXR1cmUgKi8KLnNpZ25hdHVyZS1wcmV2aWV3IHsgbWF4LXdpZHRoOiAyMjBweDsgbWF4LWhlaWdodDogOTBweDsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogOHB4OyBwYWRkaW5nOiA4cHg7IGJhY2tncm91bmQ6ICNmYWZjZmE7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAxMnB4OyB9CgovKiBNZXNzYWdlcyAqLwoubXNnLWxheW91dCB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMjIwcHggMWZyOyBnYXA6IDE2cHg7IGhlaWdodDogNTYwcHg7IH0KLm1zZy1jb250YWN0cyB7IGJhY2tncm91bmQ6IHZhcigtLWNhcmQpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOyBvdmVyZmxvdy15OiBhdXRvOyBwYWRkaW5nOiA2cHg7IH0KLm1zZy1jb250YWN0IHsgcGFkZGluZzogMTBweCAxMnB4OyBib3JkZXItcmFkaXVzOiA4cHg7IGN1cnNvcjogcG9pbnRlcjsgZm9udC1zaXplOiAxNHB4OyB9Ci5tc2ctY29udGFjdDpob3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLWJnKTsgfQoubXNnLWNvbnRhY3QuYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeSk7IGNvbG9yOiAjZmZmOyB9Ci5tc2ctY29udGFjdCAubXV0ZWQtcm9sZSB7IGZvbnQtc2l6ZTogMTFweDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgb3BhY2l0eTogMC43OyB9Ci5tc2ctdGhyZWFkIHsgYmFja2dyb3VuZDogdmFyKC0tY2FyZCk7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IG92ZXJmbG93OiBoaWRkZW47IH0KLm1zZy1zY3JvbGwgeyBmbGV4OiAxOyBvdmVyZmxvdy15OiBhdXRvOyBwYWRkaW5nOiAxNnB4OyB9Ci5tc2ctYnViYmxlIHsgbWF4LXdpZHRoOiA3MCU7IHBhZGRpbmc6IDhweCAxMnB4OyBib3JkZXItcmFkaXVzOiAxMnB4OyBtYXJnaW4tYm90dG9tOiAxMHB4OyBmb250LXNpemU6IDE0cHg7IGJhY2tncm91bmQ6IHZhcigtLWJnKTsgfQoubXNnLWJ1YmJsZS5taW5lIHsgbWFyZ2luLWxlZnQ6IGF1dG87IGJhY2tncm91bmQ6IHZhcigtLXByaW1hcnkpOyBjb2xvcjogI2ZmZjsgfQoubXNnLWJ1YmJsZSAubXNnLXNlbmRlciB7IGZvbnQtc2l6ZTogMTFweDsgZm9udC13ZWlnaHQ6IDcwMDsgb3BhY2l0eTogMC43NTsgbWFyZ2luLWJvdHRvbTogMnB4OyB9Ci5tc2ctYnViYmxlIC5tc2ctdGltZSB7IGZvbnQtc2l6ZTogMTBweDsgb3BhY2l0eTogMC42OyBtYXJnaW4tdG9wOiAzcHg7IH0KLm1zZy1jb21wb3NlIHsgZGlzcGxheTogZmxleDsgZ2FwOiA4cHg7IHBhZGRpbmc6IDEycHg7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9Ci5tc2ctY29tcG9zZSB0ZXh0YXJlYSB7IGZsZXg6IDE7IG1pbi1oZWlnaHQ6IDQwcHg7IHJlc2l6ZTogbm9uZTsgcGFkZGluZzogOXB4IDExcHg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDhweDsgZm9udC1mYW1pbHk6IGluaGVyaXQ7IH0KCi8qIEJ1dHRvbnMgKi8KLmJ0biB7CiAgZGlzcGxheTogaW5saW5lLWZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICBnYXA6IDZweDsKICBwYWRkaW5nOiA5cHggMTZweDsKICBib3JkZXItcmFkaXVzOiA4cHg7CiAgYm9yZGVyOiAxcHggc29saWQgdHJhbnNwYXJlbnQ7CiAgZm9udC1zaXplOiAxNHB4OwogIGZvbnQtd2VpZ2h0OiA2MDA7CiAgY3Vyc29yOiBwb2ludGVyOwogIGJhY2tncm91bmQ6IHZhcigtLWJvcmRlcik7CiAgY29sb3I6IHZhcigtLXRleHQpOwp9Ci5idG4tcHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXByaW1hcnkpOyBjb2xvcjogI2ZmZjsgfQouYnRuLXByaW1hcnk6aG92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5LWRhcmspOyB9Ci5idG4tZGFuZ2VyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmZmY7IH0KLmJ0bi1naG9zdCB7IGJhY2tncm91bmQ6IHRyYW5zcGFyZW50OyBjb2xvcjogI2Q3ZGVkOTsgYm9yZGVyOiAxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjI1KTsgfQouYnRuLWdob3N0OmhvdmVyIHsgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwwLjA4KTsgfQouYnRuLWJsb2NrIHsgd2lkdGg6IDEwMCU7IG1hcmdpbi10b3A6IDE4cHg7IH0KLmJ0bi1zbSB7IHBhZGRpbmc6IDVweCAxMHB4OyBmb250LXNpemU6IDEycHg7IH0KLmJ0bi1pY29uIHsgYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7IGJvcmRlcjogbm9uZTsgZm9udC1zaXplOiAyMnB4OyBjdXJzb3I6IHBvaW50ZXI7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGxpbmUtaGVpZ2h0OiAxOyB9CgovKiBBcHAgc2hlbGwgKi8KLmFwcCB7IGRpc3BsYXk6IGZsZXg7IG1pbi1oZWlnaHQ6IDEwMHZoOyB9Ci5zaWRlYmFyIHsKICB3aWR0aDogMjIwcHg7CiAgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeS1kYXJrKTsKICBjb2xvcjogI2ZmZjsKICBkaXNwbGF5OiBmbGV4OwogIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgcGFkZGluZzogMjBweCAwOwogIGZsZXgtc2hyaW5rOiAwOwp9Ci5icmFuZCB7CiAgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAxMHB4OwogIHBhZGRpbmc6IDAgMThweCAxOHB4OyBtYXJnaW4tYm90dG9tOiA2cHg7CiAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4xMik7Cn0KLmJyYW5kLWVuIHsgZm9udC13ZWlnaHQ6IDgwMDsgZm9udC1zaXplOiAxNHB4OyBsaW5lLWhlaWdodDogMS4yNTsgfQouYnJhbmQtYXIgeyBmb250LXNpemU6IDEycHg7IGNvbG9yOiAjYjljOWMwOyBkaXJlY3Rpb246IHJ0bDsgbWFyZ2luLXRvcDogMXB4OyB9Ci5zaWRlYmFyIG5hdiB7IGZsZXg6IDE7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMnB4OyB9Ci5zaWRlYmFyIG5hdiBhIHsKICBjb2xvcjogI2NmZDhkMzsKICB0ZXh0LWRlY29yYXRpb246IG5vbmU7CiAgcGFkZGluZzogMTBweCAyMHB4OwogIGZvbnQtc2l6ZTogMTRweDsKICBmb250LXdlaWdodDogNTAwOwogIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdHJhbnNwYXJlbnQ7CiAgY3Vyc29yOiBwb2ludGVyOwp9Ci5zaWRlYmFyIG5hdiBhOmhvdmVyIHsgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwwLjA2KTsgY29sb3I6ICNmZmY7IH0KLnNpZGViYXIgbmF2IGEuYWN0aXZlIHsgYmFja2dyb3VuZDogcmdiYSgyNTUsMjU1LDI1NSwwLjEpOyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tYWNjZW50KTsgY29sb3I6ICNmZmY7IH0KLnNpZGViYXItZm9vdGVyIHsgcGFkZGluZzogMTZweCAyMHB4IDA7IGJvcmRlci10b3A6IDFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMTIpOyBtYXJnaW4tdG9wOiAxMHB4OyB9Ci51c2VyLWJhZGdlIHsgZm9udC1zaXplOiAxM3B4OyBtYXJnaW4tYm90dG9tOiAxMHB4OyB9Ci51c2VyLWJhZGdlIC5yb2xlLXBpbGwgeyBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7IG1hcmdpbi10b3A6IDRweDsgZm9udC1zaXplOiAxMXB4OyB0ZXh0LXRyYW5zZm9ybTogdXBwZXJjYXNlOyBsZXR0ZXItc3BhY2luZzogMC41cHg7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiAjZmZmOyBwYWRkaW5nOiAycHggOHB4OyBib3JkZXItcmFkaXVzOiA5OTlweDsgfQoKLm1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KLnRvcGJhciB7IHBhZGRpbmc6IDIycHggMzJweDsgYmFja2dyb3VuZDogdmFyKC0tY2FyZCk7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItdG9wOiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsgfQoudG9wYmFyIGgyIHsgbWFyZ2luOiAwOyBmb250LXNpemU6IDIwcHg7IH0KLnRvcGJhci1zdWIgeyBmb250LXNpemU6IDEycHg7IG1hcmdpbi10b3A6IDJweDsgfQoudmlldyB7IHBhZGRpbmc6IDI0cHggMzJweDsgbWF4LXdpZHRoOiAxMTAwcHg7IH0KCi8qIENhcmRzIC8gZ3JpZCAqLwouZ3JpZCB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogcmVwZWF0KGF1dG8tZml0LCBtaW5tYXgoMjAwcHgsIDFmcikpOyBnYXA6IDE2cHg7IG1hcmdpbi1ib3R0b206IDI0cHg7IH0KLnN0YXQtY2FyZCB7IGJhY2tncm91bmQ6IHZhcigtLWNhcmQpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOyBwYWRkaW5nOiAxOHB4OyB9Ci5zdGF0LWNhcmQgLm51bSB7IGZvbnQtc2l6ZTogMjhweDsgZm9udC13ZWlnaHQ6IDgwMDsgY29sb3I6IHZhcigtLXByaW1hcnkpOyB9Ci5zdGF0LWNhcmQgLmxhYmVsIHsgZm9udC1zaXplOiAxM3B4OyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBtYXJnaW4tdG9wOiA0cHg7IH0KCi5jYXJkIHsgYmFja2dyb3VuZDogdmFyKC0tY2FyZCk7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7IHBhZGRpbmc6IDIwcHg7IG1hcmdpbi1ib3R0b206IDIwcHg7IH0KLmNhcmQtaGVhZGVyIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBtYXJnaW4tYm90dG9tOiAxNHB4OyB9Ci5jYXJkLWhlYWRlciBoMyB7IG1hcmdpbjogMDsgZm9udC1zaXplOiAxNnB4OyB9CgovKiBUYWJsZSAqLwp0YWJsZSB7IHdpZHRoOiAxMDAlOyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyBmb250LXNpemU6IDE0cHg7IH0KdGgsIHRkIHsgdGV4dC1hbGlnbjogbGVmdDsgcGFkZGluZzogMTBweCA4cHg7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB2ZXJ0aWNhbC1hbGlnbjogdG9wOyB9CnRoIHsgZm9udC1zaXplOiAxMnB4OyB0ZXh0LXRyYW5zZm9ybTogdXBwZXJjYXNlOyBsZXR0ZXItc3BhY2luZzogMC40cHg7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGZvbnQtd2VpZ2h0OiA3MDA7IH0KdHI6bGFzdC1jaGlsZCB0ZCB7IGJvcmRlci1ib3R0b206IG5vbmU7IH0KLmVtcHR5LXJvdyB0ZCB7IHRleHQtYWxpZ246IGNlbnRlcjsgY29sb3I6IHZhcigtLW11dGVkKTsgcGFkZGluZzogMjRweCAwOyB9CgovKiBCYWRnZXMgKi8KLmJhZGdlIHsgZGlzcGxheTogaW5saW5lLWJsb2NrOyBwYWRkaW5nOiAzcHggOXB4OyBib3JkZXItcmFkaXVzOiA5OTlweDsgZm9udC1zaXplOiAxMXB4OyBmb250LXdlaWdodDogNzAwOyB0ZXh0LXRyYW5zZm9ybTogdXBwZXJjYXNlOyBsZXR0ZXItc3BhY2luZzogMC4zcHg7IH0KLmJhZGdlLW9wZW4sIC5iYWRnZS1uZXcgeyBiYWNrZ3JvdW5kOiAjZmRlY2VhOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQouYmFkZ2UtaW5fcHJvZ3Jlc3MsIC5iYWRnZS1pbl9yZXZpZXcgeyBiYWNrZ3JvdW5kOiAjZmRmM2UyOyBjb2xvcjogdmFyKC0td2FybmluZyk7IH0KLmJhZGdlLXJlc29sdmVkLCAuYmFkZ2UtaW1wbGVtZW50ZWQsIC5iYWRnZS1hcHByb3ZlZCwgLmJhZGdlLXJldmlld2VkIHsgYmFja2dyb3VuZDogI2U2ZjNlYzsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9Ci5iYWRnZS1yZWplY3RlZCB7IGJhY2tncm91bmQ6ICNmMGYwZjA7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IH0KLmJhZGdlLW9uX3RyYWNrIHsgYmFja2dyb3VuZDogI2U2ZjNlYzsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9Ci5iYWRnZS1hdF9yaXNrIHsgYmFja2dyb3VuZDogI2ZkZjNlMjsgY29sb3I6IHZhcigtLXdhcm5pbmcpOyB9Ci5iYWRnZS1vZmZfdHJhY2sgeyBiYWNrZ3JvdW5kOiAjZmRlY2VhOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQouYmFkZ2Utc3VibWl0dGVkIHsgYmFja2dyb3VuZDogI2VlZjFmNjsgY29sb3I6ICMzYzVhOGE7IH0KCi8qIEZvcm1zICovCi5mb3JtLXJvdyB7IG1hcmdpbi1ib3R0b206IDE0cHg7IH0KLmZvcm0tcm93IGxhYmVsIHsgZGlzcGxheTogYmxvY2s7IGZvbnQtc2l6ZTogMTNweDsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luLWJvdHRvbTogNnB4OyB9Ci5mb3JtLXJvdyBpbnB1dCwgLmZvcm0tcm93IHNlbGVjdCwgLmZvcm0tcm93IHRleHRhcmVhIHsKICB3aWR0aDogMTAwJTsgcGFkZGluZzogOXB4IDExcHg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDhweDsgZm9udC1zaXplOiAxNHB4OyBmb250LWZhbWlseTogaW5oZXJpdDsKfQouZm9ybS1yb3cgdGV4dGFyZWEgeyBtaW4taGVpZ2h0OiA4MHB4OyByZXNpemU6IHZlcnRpY2FsOyB9Ci5mb3JtLWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IGZsZXgtZW5kOyBnYXA6IDEwcHg7IG1hcmdpbi10b3A6IDE4cHg7IH0KLnR3by1jb2wgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IGdhcDogMTRweDsgfQoKLyogTW9kYWwgKi8KLm1vZGFsLW92ZXJsYXkgewogIHBvc2l0aW9uOiBmaXhlZDsgaW5zZXQ6IDA7IGJhY2tncm91bmQ6IHJnYmEoMjAsMjUsMjIsMC41KTsKICBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgei1pbmRleDogNTA7IHBhZGRpbmc6IDIwcHg7Cn0KLm1vZGFsIHsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsgd2lkdGg6IDQ4MHB4OyBtYXgtd2lkdGg6IDEwMCU7IG1heC1oZWlnaHQ6IDkwdmg7IG92ZXJmbG93LXk6IGF1dG87IH0KLm1vZGFsLWhlYWRlciB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgcGFkZGluZzogMThweCAyMHB4OyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQoubW9kYWwtaGVhZGVyIGgzIHsgbWFyZ2luOiAwOyBmb250LXNpemU6IDE2cHg7IH0KLm1vZGFsLWJvZHkgeyBwYWRkaW5nOiAyMHB4OyB9CgovKiBUb2FzdCAqLwoudG9hc3QgewogIHBvc2l0aW9uOiBmaXhlZDsgYm90dG9tOiAyNHB4OyBsZWZ0OiA1MCU7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5LWRhcmspOyBjb2xvcjogI2ZmZjsgcGFkZGluZzogMTJweCAyMHB4OyBib3JkZXItcmFkaXVzOiA4cHg7IGZvbnQtc2l6ZTogMTRweDsgei1pbmRleDogMTAwOwogIGJveC1zaGFkb3c6IDAgMTBweCAyNXB4IHJnYmEoMCwwLDAsMC4yNSk7Cn0KLnRvYXN0LmVycm9yIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQoKLyogUHJvZ3Jlc3MgYmFyICovCi5wcm9ncmVzcyB7IGJhY2tncm91bmQ6IHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBoZWlnaHQ6IDhweDsgb3ZlcmZsb3c6IGhpZGRlbjsgbWFyZ2luLXRvcDogOHB4OyB9Ci5wcm9ncmVzcy1maWxsIHsgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeSk7IGhlaWdodDogMTAwJTsgfQoKLnNlY3Rpb24tdG9vbGJhciB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgYWxpZ24taXRlbXM6IGNlbnRlcjsgbWFyZ2luLWJvdHRvbTogMTZweDsgfQouc21hbGwtbm90ZSB7IGZvbnQtc2l6ZTogMTJweDsgY29sb3I6IHZhcigtLW11dGVkKTsgbWFyZ2luLXRvcDogNnB4OyB9Ci5saW5rIHsgY29sb3I6IHZhcigtLXByaW1hcnkpOyB0ZXh0LWRlY29yYXRpb246IG5vbmU7IGZvbnQtd2VpZ2h0OiA2MDA7IH0KLmxpbms6aG92ZXIgeyB0ZXh0LWRlY29yYXRpb246IHVuZGVybGluZTsgfQoucHJldmlldy10YWJsZS13cmFwIHsgbWF4LWhlaWdodDogMzIwcHg7IG92ZXJmbG93OiBhdXRvOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiA4cHg7IG1hcmdpbi10b3A6IDEwcHg7IH0KCkBtZWRpYSAobWF4LXdpZHRoOiA4MDBweCkgewogIC5hcHAgeyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyB9CgogIC8qIFNpZGViYXIgYmVjb21lcyBhIGNvbXBhY3QgdG9wIGJhcjogYnJhbmQsIHRoZW4gYSBob3Jpem9udGFsbHktc2Nyb2xsaW5nCiAgICAgbmF2IHN0cmlwLCB0aGVuIGEgaG9yaXpvbnRhbGx5LXNjcm9sbGluZyBhY3Rpb24gYmFyLiBOb3RoaW5nIGlzIGhpZGRlbi4gKi8KICAuc2lkZWJhciB7IHdpZHRoOiAxMDAlOyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBwYWRkaW5nOiAxMHB4IDA7IH0KICAuYnJhbmQgeyBwYWRkaW5nOiAwIDE0cHggMTBweDsgbWFyZ2luLWJvdHRvbTogNHB4OyB9CiAgLnNpZGViYXIgbmF2IHsKICAgIGZsZXg6IG5vbmU7CiAgICBmbGV4LWRpcmVjdGlvbjogcm93OwogICAgb3ZlcmZsb3cteDogYXV0bzsKICAgIC13ZWJraXQtb3ZlcmZsb3ctc2Nyb2xsaW5nOiB0b3VjaDsKICAgIGdhcDogMnB4OwogICAgcGFkZGluZzogMCAxMHB4IDhweDsKICB9CiAgLnNpZGViYXIgbmF2IGEgewogICAgZmxleDogbm9uZTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICBwYWRkaW5nOiA4cHggMTJweDsKICAgIGJvcmRlci1sZWZ0OiBub25lOwogICAgYm9yZGVyLWJvdHRvbTogM3B4IHNvbGlkIHRyYW5zcGFyZW50OwogICAgYm9yZGVyLXJhZGl1czogNnB4OwogIH0KICAuc2lkZWJhciBuYXYgYS5hY3RpdmUgeyBib3JkZXItbGVmdC1jb2xvcjogdHJhbnNwYXJlbnQ7IGJvcmRlci1ib3R0b20tY29sb3I6IHZhcigtLWFjY2VudCk7IH0KICAuc2lkZWJhci1mb290ZXIgewogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiByb3c7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgb3ZlcmZsb3cteDogYXV0bzsKICAgIC13ZWJraXQtb3ZlcmZsb3ctc2Nyb2xsaW5nOiB0b3VjaDsKICAgIGdhcDogOHB4OwogICAgcGFkZGluZzogMTBweCAxNHB4OwogICAgbWFyZ2luLXRvcDogNHB4OwogIH0KICAuc2lkZWJhci1mb290ZXIgLnVzZXItYmFkZ2UgeyBmbGV4OiBub25lOyBtYXJnaW4tYm90dG9tOiAwOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnNpZGViYXItZm9vdGVyIC51c2VyLWJhZGdlIC5tdXRlZCB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2lkZWJhci1mb290ZXIgLmJ0biB7IGZsZXg6IG5vbmU7IHdpZHRoOiBhdXRvOyB3aGl0ZS1zcGFjZTogbm93cmFwOyBtYXJnaW4tdG9wOiAwOyB9CgogIC50b3BiYXIgeyBwYWRkaW5nOiAxNHB4IDE2cHg7IH0KICAudG9wYmFyIGgyIHsgZm9udC1zaXplOiAxN3B4OyB9CiAgLnZpZXcgeyBwYWRkaW5nOiAxNHB4OyB9CgogIC5zZWN0aW9uLXRvb2xiYXIgeyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBhbGlnbi1pdGVtczogc3RyZXRjaDsgZ2FwOiAxMHB4OyB9CiAgLnNlY3Rpb24tdG9vbGJhciA+IGRpdiB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogOHB4OyB9CiAgLmNhcmQtaGVhZGVyIHsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7IGdhcDogMTBweDsgfQogIC5jYXJkLWhlYWRlciA+IGRpdjpsYXN0LWNoaWxkIHsgZGlzcGxheTogZmxleDsgZmxleC13cmFwOiB3cmFwOyBnYXA6IDhweDsgfQoKICAudHdvLWNvbCB7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyOyB9CgogIC8qIFRhYmxlcyBzY3JvbGwgaG9yaXpvbnRhbGx5IGluc3RlYWQgb2Ygc3F1YXNoaW5nIHVucmVhZGFibHkgKi8KICAuY2FyZCB7IG92ZXJmbG93LXg6IGF1dG87IH0KICB0YWJsZSB7IG1pbi13aWR0aDogNTIwcHg7IH0KCiAgLyogUHJldmVudCBpT1MgU2FmYXJpIGZyb20gem9vbWluZyBpbiBvbiBmb2N1cyAqLwogIGlucHV0LCBzZWxlY3QsIHRleHRhcmVhLCBidXR0b24geyBmb250LXNpemU6IDE2cHg7IH0KICAuYnRuLXNtIHsgZm9udC1zaXplOiAxM3B4OyB9CgogIC5sb2dpbi1jYXJkIHsgcGFkZGluZzogMjhweCAyMHB4OyB9CgogIC8qIE1lc3NhZ2VzOiBzdGFjayBjb250YWN0cyBhYm92ZSB0aGUgdGhyZWFkIGluc3RlYWQgb2Ygc2lkZS1ieS1zaWRlICovCiAgLm1zZy1sYXlvdXQgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmcjsgaGVpZ2h0OiBhdXRvOyB9CiAgLm1zZy1jb250YWN0cyB7IG1heC1oZWlnaHQ6IDE0MHB4OyB9CiAgLm1zZy10aHJlYWQgeyBoZWlnaHQ6IDQyMHB4OyB9Cn0K', 'base64').toString('utf8');
const APP_JS = Buffer.from('Ly8gYXBwLmpzIC0gVm9sdW50ZWVyIE1hbmFnZW1lbnQgU3lzdGVtIGZyb250ZW5kICh2YW5pbGxhIEpTLCBubyBidWlsZCBzdGVwKQoKY29uc3Qgc3RhdGUgPSB7CiAgdG9rZW46IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd2bXNfdG9rZW4nKSB8fCBudWxsLAogIHVzZXI6IG51bGwsCiAgcm91dGU6ICdkYXNoYm9hcmQnLAp9OwoKLy8gLS0tLS0tLS0tLSBBUEkgaGVscGVyIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gYXBpKG1ldGhvZCwgcGF0aCwgYm9keSkgewogIGNvbnN0IG9wdHMgPSB7IG1ldGhvZCwgaGVhZGVyczoge30gfTsKICBpZiAoc3RhdGUudG9rZW4pIG9wdHMuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gJ0JlYXJlciAnICsgc3RhdGUudG9rZW47CiAgaWYgKGJvZHkgIT09IHVuZGVmaW5lZCkgewogICAgb3B0cy5oZWFkZXJzWydDb250ZW50LVR5cGUnXSA9ICdhcHBsaWNhdGlvbi9qc29uJzsKICAgIG9wdHMuYm9keSA9IEpTT04uc3RyaW5naWZ5KGJvZHkpOwogIH0KICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCBvcHRzKTsKICBsZXQgZGF0YSA9IG51bGw7CiAgdHJ5IHsgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7IH0gY2F0Y2ggeyBkYXRhID0gbnVsbDsgfQogIGlmICghcmVzLm9rKSB7CiAgICBjb25zdCBtc2cgPSAoZGF0YSAmJiBkYXRhLmVycm9yKSB8fCBgUmVxdWVzdCBmYWlsZWQgKCR7cmVzLnN0YXR1c30pYDsKICAgIHRocm93IG5ldyBFcnJvcihtc2cpOwogIH0KICByZXR1cm4gZGF0YTsKfQoKLy8gLS0tLS0tLS0tLSBUb2FzdCAtLS0tLS0tLS0tCmxldCB0b2FzdFRpbWVyOwpmdW5jdGlvbiBzaG93VG9hc3QobXNnLCBpc0Vycm9yKSB7CiAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndG9hc3QnKTsKICBlbC50ZXh0Q29udGVudCA9IG1zZzsKICBlbC5jbGFzc05hbWUgPSAndG9hc3QnICsgKGlzRXJyb3IgPyAnIGVycm9yJyA6ICcnKTsKICBjbGVhclRpbWVvdXQodG9hc3RUaW1lcik7CiAgdG9hc3RUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4gZWwuY2xhc3NMaXN0LmFkZCgnaGlkZGVuJyksIDMyMDApOwp9CgovLyAtLS0tLS0tLS0tIE1vZGFsIC0tLS0tLS0tLS0KZnVuY3Rpb24gb3Blbk1vZGFsKHRpdGxlLCBib2R5SHRtbCkgewogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbFRpdGxlJykudGV4dENvbnRlbnQgPSB0aXRsZTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWxCb2R5JykuaW5uZXJIVE1MID0gYm9keUh0bWw7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsT3ZlcmxheScpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwp9CmZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsT3ZlcmxheScpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbEJvZHknKS5pbm5lckhUTUwgPSAnJzsKfQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWxDbG9zZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VNb2RhbCk7CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbE92ZXJsYXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIChlKSA9PiB7CiAgaWYgKGUudGFyZ2V0LmlkID09PSAnbW9kYWxPdmVybGF5JykgY2xvc2VNb2RhbCgpOwp9KTsKCi8vIC0tLS0tLS0tLS0gVXRpbHMgLS0tLS0tLS0tLQpmdW5jdGlvbiBlc2MocykgewogIGlmIChzID09PSBudWxsIHx8IHMgPT09IHVuZGVmaW5lZCkgcmV0dXJuICcnOwogIHJldHVybiBTdHJpbmcocykucmVwbGFjZSgvWyY8PiInXS9nLCAoYykgPT4gKHsgJyYnOiAnJmFtcDsnLCAnPCc6ICcmbHQ7JywgJz4nOiAnJmd0OycsICciJzogJyZxdW90OycsICInIjogJyYjMzk7JyB9W2NdKSk7Cn0KZnVuY3Rpb24gZm10RGF0ZShzKSB7CiAgaWYgKCFzKSByZXR1cm4gJyc7CiAgcmV0dXJuIHMucmVwbGFjZSgnVCcsICcgJykuc2xpY2UoMCwgMTYpOwp9CmZ1bmN0aW9uIGJhZGdlKHN0YXR1cykgewogIHJldHVybiBgPHNwYW4gY2xhc3M9ImJhZGdlIGJhZGdlLSR7ZXNjKHN0YXR1cyl9Ij4ke2VzYygoc3RhdHVzIHx8ICcnKS5yZXBsYWNlKC9fL2csICcgJykpfTwvc3Bhbj5gOwp9CgovLyAtLS0tLS0tLS0tIEF1dGggLS0tLS0tLS0tLQpsZXQgbG9naW5UYWIgPSAnbWFuYWdlcic7CmZ1bmN0aW9uIHNldExvZ2luVGFiKHRhYikgewogIGxvZ2luVGFiID0gdGFiOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YWJNYW5hZ2VyJykuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgdGFiID09PSAnbWFuYWdlcicpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YWJWb2x1bnRlZXInKS5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCB0YWIgPT09ICd2b2x1bnRlZXInKTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9naW5FcnJvcicpLnRleHRDb250ZW50ID0gJyc7Cn0KZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhYk1hbmFnZXInKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHNldExvZ2luVGFiKCdtYW5hZ2VyJykpOwpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGFiVm9sdW50ZWVyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiBzZXRMb2dpblRhYigndm9sdW50ZWVyJykpOwoKZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luRm9ybScpLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChlKSA9PiB7CiAgZS5wcmV2ZW50RGVmYXVsdCgpOwogIGNvbnN0IGVtYWlsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luRW1haWwnKS52YWx1ZS50cmltKCk7CiAgY29uc3QgcGFzc3dvcmQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9naW5QYXNzd29yZCcpLnZhbHVlOwogIGNvbnN0IGVyckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luRXJyb3InKTsKICBlcnJFbC50ZXh0Q29udGVudCA9ICcnOwogIHRyeSB7CiAgICBjb25zdCBkYXRhID0gYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvbG9naW4nLCB7IGVtYWlsLCBwYXNzd29yZCB9KTsKICAgIGNvbnN0IHJvbGUgPSBkYXRhLnVzZXIucm9sZTsKICAgIGlmIChsb2dpblRhYiA9PT0gJ3ZvbHVudGVlcicgJiYgcm9sZSAhPT0gJ3ZvbHVudGVlcicpIHsKICAgICAgZXJyRWwudGV4dENvbnRlbnQgPSAnVGhpcyBsb29rcyBsaWtlIGEgbWFuYWdlciBhY2NvdW50LiBTd2l0Y2ggdG8gdGhlICJNYW5hZ2VyIExvZ2luIiB0YWIgYWJvdmUuJzsKICAgICAgcmV0dXJuOwogICAgfQogICAgaWYgKGxvZ2luVGFiID09PSAnbWFuYWdlcicgJiYgcm9sZSA9PT0gJ3ZvbHVudGVlcicpIHsKICAgICAgZXJyRWwudGV4dENvbnRlbnQgPSAnVGhpcyBsb29rcyBsaWtlIGEgdm9sdW50ZWVyIGFjY291bnQuIFN3aXRjaCB0byB0aGUgIlZvbHVudGVlciBMb2dpbiIgdGFiIGFib3ZlLic7CiAgICAgIHJldHVybjsKICAgIH0KICAgIHN0YXRlLnRva2VuID0gZGF0YS50b2tlbjsKICAgIHN0YXRlLnVzZXIgPSBkYXRhLnVzZXI7CiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndm1zX3Rva2VuJywgZGF0YS50b2tlbik7CiAgICBib290KCk7CiAgfSBjYXRjaCAoZXJyKSB7CiAgICBlcnJFbC50ZXh0Q29udGVudCA9IGVyci5tZXNzYWdlOwogIH0KfSk7Cgpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9nb3V0QnRuJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgc3RhdGUudG9rZW4gPSBudWxsOwogIHN0YXRlLnVzZXIgPSBudWxsOwogIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd2bXNfdG9rZW4nKTsKICBsb2NhdGlvbi5yZWxvYWQoKTsKfSk7Cgpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhbmdlUHdCdG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICBvcGVuTW9kYWwoJ0NoYW5nZSBwYXNzd29yZCcsIGAKICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+Q3VycmVudCBwYXNzd29yZDwvbGFiZWw+PGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0icHdDdXJyZW50IiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5OZXcgcGFzc3dvcmQgKG1pbiA2IGNoYXJhY3RlcnMpPC9sYWJlbD48aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJwd05ldyIgLz48L2Rpdj4KICAgIDxwIGlkPSJwd0Vycm9yIiBjbGFzcz0iZXJyb3ItdGV4dCI+PC9wPgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdFBhc3N3b3JkQ2hhbmdlKCkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9KTsKYXN5bmMgZnVuY3Rpb24gc3VibWl0UGFzc3dvcmRDaGFuZ2UoKSB7CiAgY29uc3QgZXJyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncHdFcnJvcicpOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9tZS9wYXNzd29yZCcsIHsKICAgICAgY3VycmVudF9wYXNzd29yZDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3B3Q3VycmVudCcpLnZhbHVlLAogICAgICBuZXdfcGFzc3dvcmQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwd05ldycpLnZhbHVlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1Bhc3N3b3JkIHVwZGF0ZWQnKTsKICB9IGNhdGNoIChlcnIpIHsKICAgIGVyckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgfQp9CgovLyAtLS0tLS0tLS0tIEVkaXQgbXkgb3duIG5hbWUgLS0tLS0tLS0tLQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZWRpdE5hbWVCdG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICBvcGVuTW9kYWwoJ0VkaXQgbXkgbmFtZScsIGAKICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RGlzcGxheSBuYW1lPC9sYWJlbD48aW5wdXQgaWQ9Im15TmFtZUlucHV0IiB2YWx1ZT0iJHtlc2Moc3RhdGUudXNlci5uYW1lKX0iIC8+PC9kaXY+CiAgICA8cCBpZD0ibXlOYW1lRXJyb3IiIGNsYXNzPSJlcnJvci10ZXh0Ij48L3A+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0TXlOYW1lKCkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9KTsKYXN5bmMgZnVuY3Rpb24gc3VibWl0TXlOYW1lKCkgewogIGNvbnN0IGVyckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ215TmFtZUVycm9yJyk7CiAgY29uc3QgbmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdteU5hbWVJbnB1dCcpLnZhbHVlLnRyaW0oKTsKICBpZiAoIW5hbWUpIHsgZXJyRWwudGV4dENvbnRlbnQgPSAnTmFtZSBjYW5ub3QgYmUgZW1wdHknOyByZXR1cm47IH0KICB0cnkgewogICAgYXdhaXQgYXBpKCdQVVQnLCBgL2FwaS91c2Vycy8ke3N0YXRlLnVzZXIuaWR9YCwgeyBuYW1lIH0pOwogICAgc3RhdGUudXNlci5uYW1lID0gbmFtZTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnTmFtZSB1cGRhdGVkJyk7CiAgICByZW5kZXJTaWRlYmFyKCk7CiAgfSBjYXRjaCAoZXJyKSB7CiAgICBlcnJFbC50ZXh0Q29udGVudCA9IGVyci5tZXNzYWdlOwogIH0KfQoKLy8gLS0tLS0tLS0tLSBNeSBzaWduYXR1cmUgKG1hbmFnZXJzIC8gVlApIC0tLS0tLS0tLS0KZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ215U2lnbmF0dXJlQnRuJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgb3Blbk1vZGFsKCdNeSBzaWduYXR1cmUnLCBgCiAgICA8cCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJtYXJnaW4tdG9wOjA7Ij5VcGxvYWQgYSBwaG90byBvciBpbWFnZSBvZiB5b3VyIHNpZ25hdHVyZSAoUE5HIG9yIEpQRUcsIG1heCA0MDBLQikuIEl0IHdpbGwgYXV0b21hdGljYWxseSBhcHBlYXIgb24gZXZlcnkgY2VydGlmaWNhdGUgeW91IGlzc3VlLjwvcD4KICAgICR7c3RhdGUudXNlci5oYXNfc2lnbmF0dXJlID8gJzxwIGNsYXNzPSJzbWFsbC1ub3RlIj5Zb3UgYWxyZWFkeSBoYXZlIGEgc2lnbmF0dXJlIHNhdmVkLiBVcGxvYWRpbmcgYSBuZXcgb25lIHdpbGwgcmVwbGFjZSBpdC48L3A+JyA6ICcnfQogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5TaWduYXR1cmUgaW1hZ2U8L2xhYmVsPjxpbnB1dCB0eXBlPSJmaWxlIiBpZD0ic2lnSW5wdXQiIGFjY2VwdD0iaW1hZ2UvcG5nLGltYWdlL2pwZWciIC8+PC9kaXY+CiAgICA8cCBpZD0ic2lnRXJyb3IiIGNsYXNzPSJlcnJvci10ZXh0Ij48L3A+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICAke3N0YXRlLnVzZXIuaGFzX3NpZ25hdHVyZSA/ICc8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWRhbmdlciIgb25jbGljaz0icmVtb3ZlTXlTaWduYXR1cmUoKSI+UmVtb3ZlIHNpZ25hdHVyZTwvYnV0dG9uPicgOiAnJ30KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdE15U2lnbmF0dXJlKCkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9KTsKYXN5bmMgZnVuY3Rpb24gc3VibWl0TXlTaWduYXR1cmUoKSB7CiAgY29uc3QgZXJyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2lnRXJyb3InKTsKICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzaWdJbnB1dCcpOwogIGlmICghaW5wdXQuZmlsZXMubGVuZ3RoKSB7IGVyckVsLnRleHRDb250ZW50ID0gJ0Nob29zZSBhbiBpbWFnZSBmaXJzdCc7IHJldHVybjsgfQogIGNvbnN0IGZpbGUgPSBpbnB1dC5maWxlc1swXTsKICBpZiAoZmlsZS5zaXplID4gNDAwICogMTAyNCkgeyBlcnJFbC50ZXh0Q29udGVudCA9ICdJbWFnZSBpcyB0b28gbGFyZ2UgKG1heCA0MDBLQiknOyByZXR1cm47IH0KICB0cnkgewogICAgY29uc3QgYjY0ID0gYXdhaXQgcmVhZEZpbGVBc0Jhc2U2NChmaWxlKTsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL21lL3NpZ25hdHVyZScsIHsgZGF0YV9iYXNlNjQ6IGI2NCB9KTsKICAgIHN0YXRlLnVzZXIuaGFzX3NpZ25hdHVyZSA9IHRydWU7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1NpZ25hdHVyZSBzYXZlZCcpOwogIH0gY2F0Y2ggKGVycikgewogICAgZXJyRWwudGV4dENvbnRlbnQgPSBlcnIubWVzc2FnZTsKICB9Cn0KYXN5bmMgZnVuY3Rpb24gcmVtb3ZlTXlTaWduYXR1cmUoKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnREVMRVRFJywgJy9hcGkvbWUvc2lnbmF0dXJlJyk7CiAgICBzdGF0ZS51c2VyLmhhc19zaWduYXR1cmUgPSBmYWxzZTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnU2lnbmF0dXJlIHJlbW92ZWQnKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIE5hdmlnYXRpb24gY29uZmlnIC0tLS0tLS0tLS0KY29uc3QgTkFWID0gewogIHZwOiBbCiAgICBbJ2Rhc2hib2FyZCcsICdEYXNoYm9hcmQnXSwKICAgIFsna3BpcycsICdLUElzJ10sCiAgICBbJ2lkZWFzJywgJ0lkZWFzJ10sCiAgICBbJ2NvbXBsYWludHMnLCAnQ29tcGxhaW50cyddLAogICAgWydyZXBvcnRzJywgJ01hbmFnZXIgUmVwb3J0cyddLAogICAgWydob3VycycsICdIb3VycyddLAogICAgWydzaGlmdHMnLCAnU2NoZWR1bGUnXSwKICAgIFsnbWVzc2FnZXMnLCAnTWVzc2FnZXMnXSwKICAgIFsnZmlsZXMnLCAnRmlsZXMnXSwKICAgIFsnc3VydmV5cycsICdTdXJ2ZXlzJ10sCiAgICBbJ3RlYW0nLCAnUGVvcGxlJ10sCiAgICBbJ2NlcnRpZmljYXRlcycsICdDZXJ0aWZpY2F0ZXMnXSwKICAgIFsnYW5ub3VuY2VtZW50cycsICdBbm5vdW5jZW1lbnRzJ10sCiAgXSwKICBtYW5hZ2VyOiBbCiAgICBbJ2Rhc2hib2FyZCcsICdEYXNoYm9hcmQnXSwKICAgIFsna3BpcycsICdNeSBLUElzJ10sCiAgICBbJ2lkZWFzJywgJ1RlYW0gSWRlYXMnXSwKICAgIFsnY29tcGxhaW50cycsICdUZWFtIENvbXBsYWludHMnXSwKICAgIFsncmVwb3J0cycsICdSZXBvcnRzIHRvIFZQJ10sCiAgICBbJ2hvdXJzJywgJ0hvdXJzJ10sCiAgICBbJ3NoaWZ0cycsICdTY2hlZHVsZSddLAogICAgWydtZXNzYWdlcycsICdNZXNzYWdlcyddLAogICAgWydmaWxlcycsICdGaWxlcyddLAogICAgWydzdXJ2ZXlzJywgJ1N1cnZleXMnXSwKICAgIFsndGVhbScsICdNeSBWb2x1bnRlZXJzJ10sCiAgICBbJ2NlcnRpZmljYXRlcycsICdDZXJ0aWZpY2F0ZXMnXSwKICAgIFsnYW5ub3VuY2VtZW50cycsICdBbm5vdW5jZW1lbnRzJ10sCiAgXSwKICB2b2x1bnRlZXI6IFsKICAgIFsnaWRlYXMnLCAnTXkgSWRlYXMnXSwKICAgIFsnY29tcGxhaW50cycsICdNeSBDb21wbGFpbnRzJ10sCiAgICBbJ2NlcnRpZmljYXRlcycsICdNeSBDZXJ0aWZpY2F0ZXMnXSwKICAgIFsnYW5ub3VuY2VtZW50cycsICdBbm5vdW5jZW1lbnRzJ10sCiAgXSwKfTsKCmNvbnN0IFRJVExFUyA9IHsKICBkYXNoYm9hcmQ6ICdEYXNoYm9hcmQnLCBrcGlzOiAnS1BJcycsIGlkZWFzOiAnSWRlYXMnLCBjb21wbGFpbnRzOiAnQ29tcGxhaW50cycsCiAgcmVwb3J0czogJ1JlcG9ydHMnLCBob3VyczogJ1ZvbHVudGVlciBIb3VycycsIHNoaWZ0czogJ1NoaWZ0IFNjaGVkdWxlJywgbWVzc2FnZXM6ICdNZXNzYWdlcycsCiAgZmlsZXM6ICdGaWxlcycsIHN1cnZleXM6ICdTdXJ2ZXlzJywgdGVhbTogJ1Blb3BsZScsIGNlcnRpZmljYXRlczogJ0NlcnRpZmljYXRlcycsIGFubm91bmNlbWVudHM6ICdBbm5vdW5jZW1lbnRzJywKfTsKCmZ1bmN0aW9uIHJlbmRlclNpZGViYXIoKSB7CiAgY29uc3QgbGlua3MgPSBOQVZbc3RhdGUudXNlci5yb2xlXTsKICBjb25zdCBuYXYgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbmF2TGlua3MnKTsKICBuYXYuaW5uZXJIVE1MID0gbGlua3MKICAgIC5tYXAoKFtrZXksIGxhYmVsXSkgPT4gYDxhIGhyZWY9IiMiIGRhdGEtcm91dGU9IiR7a2V5fSIgY2xhc3M9IiR7c3RhdGUucm91dGUgPT09IGtleSA/ICdhY3RpdmUnIDogJyd9Ij4ke2xhYmVsfTwvYT5gKQogICAgLmpvaW4oJycpOwogIG5hdi5xdWVyeVNlbGVjdG9yQWxsKCdhJykuZm9yRWFjaCgoYSkgPT4gewogICAgYS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgbmF2aWdhdGUoYS5kYXRhc2V0LnJvdXRlKTsKICAgIH0pOwogIH0pOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1c2VyQmFkZ2UnKS5pbm5lckhUTUwgPQogICAgYDxkaXY+PHN0cm9uZz4ke2VzYyhzdGF0ZS51c2VyLm5hbWUpfTwvc3Ryb25nPjwvZGl2PjxkaXYgY2xhc3M9Im11dGVkIj4ke2VzYyhzdGF0ZS51c2VyLmVtYWlsKX08L2Rpdj48c3BhbiBjbGFzcz0icm9sZS1waWxsIj4ke2VzYyhzdGF0ZS51c2VyLnJvbGUpfTwvc3Bhbj5gOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdteVNpZ25hdHVyZUJ0bicpLmNsYXNzTGlzdC50b2dnbGUoJ2hpZGRlbicsIHN0YXRlLnVzZXIucm9sZSA9PT0gJ3ZvbHVudGVlcicpOwp9CgpmdW5jdGlvbiBuYXZpZ2F0ZShyb3V0ZSkgewogIHN0YXRlLnJvdXRlID0gcm91dGU7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3BhZ2VUaXRsZScpLnRleHRDb250ZW50ID0gVElUTEVTW3JvdXRlXSB8fCAnJzsKICByZW5kZXJTaWRlYmFyKCk7CiAgcmVuZGVyVmlldygpOwp9Cgphc3luYyBmdW5jdGlvbiByZW5kZXJWaWV3KCkgewogIGNvbnN0IHZpZXcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndmlldycpOwogIHZpZXcuaW5uZXJIVE1MID0gJzxwIGNsYXNzPSJtdXRlZCI+TG9hZGluZy4uLjwvcD4nOwogIHRyeSB7CiAgICBzd2l0Y2ggKHN0YXRlLnJvdXRlKSB7CiAgICAgIGNhc2UgJ2Rhc2hib2FyZCc6IHJldHVybiBhd2FpdCB2aWV3RGFzaGJvYXJkKHZpZXcpOwogICAgICBjYXNlICdrcGlzJzogcmV0dXJuIGF3YWl0IHZpZXdLcGlzKHZpZXcpOwogICAgICBjYXNlICdpZGVhcyc6IHJldHVybiBhd2FpdCB2aWV3SWRlYXModmlldyk7CiAgICAgIGNhc2UgJ2NvbXBsYWludHMnOiByZXR1cm4gYXdhaXQgdmlld0NvbXBsYWludHModmlldyk7CiAgICAgIGNhc2UgJ3JlcG9ydHMnOiByZXR1cm4gYXdhaXQgdmlld1JlcG9ydHModmlldyk7CiAgICAgIGNhc2UgJ2hvdXJzJzogcmV0dXJuIGF3YWl0IHZpZXdIb3Vycyh2aWV3KTsKICAgICAgY2FzZSAnc2hpZnRzJzogcmV0dXJuIGF3YWl0IHZpZXdTaGlmdHModmlldyk7CiAgICAgIGNhc2UgJ21lc3NhZ2VzJzogcmV0dXJuIGF3YWl0IHZpZXdNZXNzYWdlcyh2aWV3KTsKICAgICAgY2FzZSAnZmlsZXMnOiByZXR1cm4gYXdhaXQgdmlld0ZpbGVzKHZpZXcpOwogICAgICBjYXNlICdzdXJ2ZXlzJzogcmV0dXJuIGF3YWl0IHZpZXdTdXJ2ZXlzKHZpZXcpOwogICAgICBjYXNlICd0ZWFtJzogcmV0dXJuIGF3YWl0IHZpZXdUZWFtKHZpZXcpOwogICAgICBjYXNlICdjZXJ0aWZpY2F0ZXMnOiByZXR1cm4gYXdhaXQgdmlld0NlcnRpZmljYXRlcyh2aWV3KTsKICAgICAgY2FzZSAnYW5ub3VuY2VtZW50cyc6IHJldHVybiBhd2FpdCB2aWV3QW5ub3VuY2VtZW50cyh2aWV3KTsKICAgICAgZGVmYXVsdDogdmlldy5pbm5lckhUTUwgPSAnPHA+Tm90IGZvdW5kPC9wPic7CiAgICB9CiAgfSBjYXRjaCAoZXJyKSB7CiAgICB2aWV3LmlubmVySFRNTCA9IGA8cCBjbGFzcz0iZXJyb3ItdGV4dCI+JHtlc2MoZXJyLm1lc3NhZ2UpfTwvcD5gOwogIH0KfQoKLy8gLS0tLS0tLS0tLSBEYXNoYm9hcmQgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3RGFzaGJvYXJkKHZpZXcpIHsKICBjb25zdCBba3Bpc1JlcywgaWRlYXNSZXMsIGNvbXBsYWludHNSZXMsIGFubm91bmNlbWVudHNSZXNdID0gYXdhaXQgUHJvbWlzZS5hbGwoWwogICAgYXBpKCdHRVQnLCAnL2FwaS9rcGlzJyksCiAgICBhcGkoJ0dFVCcsICcvYXBpL2lkZWFzJyksCiAgICBhcGkoJ0dFVCcsICcvYXBpL2NvbXBsYWludHMnKSwKICAgIGFwaSgnR0VUJywgJy9hcGkvYW5ub3VuY2VtZW50cycpLAogIF0pOwogIGNvbnN0IG9wZW5Db21wbGFpbnRzID0gY29tcGxhaW50c1Jlcy5jb21wbGFpbnRzLmZpbHRlcigoYykgPT4gYy5zdGF0dXMgIT09ICdyZXNvbHZlZCcpLmxlbmd0aDsKICBjb25zdCBuZXdJZGVhcyA9IGlkZWFzUmVzLmlkZWFzLmZpbHRlcigoaSkgPT4gaS5zdGF0dXMgPT09ICduZXcnKS5sZW5ndGg7CiAgY29uc3Qga3BpcyA9IGtwaXNSZXMua3BpczsKCiAgbGV0IHJlcG9ydHNDYXJkID0gJyc7CiAgaWYgKHN0YXRlLnVzZXIucm9sZSAhPT0gJ3ZvbHVudGVlcicpIHsKICAgIGNvbnN0IHJlcG9ydHNSZXMgPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3JlcG9ydHMnKTsKICAgIGNvbnN0IHBlbmRpbmcgPSByZXBvcnRzUmVzLnJlcG9ydHMuZmlsdGVyKChyKSA9PiByLnN0YXR1cyA9PT0gJ3N1Ym1pdHRlZCcpLmxlbmd0aDsKICAgIHJlcG9ydHNDYXJkID0gYDxkaXYgY2xhc3M9InN0YXQtY2FyZCI+PGRpdiBjbGFzcz0ibnVtIj4ke3BlbmRpbmd9PC9kaXY+PGRpdiBjbGFzcz0ibGFiZWwiPlJlcG9ydHMgYXdhaXRpbmcgcmV2aWV3PC9kaXY+PC9kaXY+YDsKICB9CgogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0iZ3JpZCI+CiAgICAgIDxkaXYgY2xhc3M9InN0YXQtY2FyZCI+PGRpdiBjbGFzcz0ibnVtIj4ke2twaXMubGVuZ3RofTwvZGl2PjxkaXYgY2xhc3M9ImxhYmVsIj5BY3RpdmUgS1BJczwvZGl2PjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzdGF0LWNhcmQiPjxkaXYgY2xhc3M9Im51bSI+JHtuZXdJZGVhc308L2Rpdj48ZGl2IGNsYXNzPSJsYWJlbCI+TmV3IGlkZWFzPC9kaXY+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InN0YXQtY2FyZCI+PGRpdiBjbGFzcz0ibnVtIj4ke29wZW5Db21wbGFpbnRzfTwvZGl2PjxkaXYgY2xhc3M9ImxhYmVsIj5PcGVuIGNvbXBsYWludHM8L2Rpdj48L2Rpdj4KICAgICAgJHtyZXBvcnRzQ2FyZH0KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj48aDM+TGF0ZXN0IGFubm91bmNlbWVudHM8L2gzPjwvZGl2PgogICAgICAke3JlbmRlckFubm91bmNlbWVudExpc3QoYW5ub3VuY2VtZW50c1Jlcy5hbm5vdW5jZW1lbnRzLnNsaWNlKDAsIDMpKX0KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj48aDM+S1BJIHNuYXBzaG90PC9oMz48L2Rpdj4KICAgICAgJHtyZW5kZXJLcGlMaXN0KGtwaXMuc2xpY2UoMCwgNCksIGZhbHNlKX0KICAgIDwvZGl2PgogIGA7Cn0KCmZ1bmN0aW9uIHJlbmRlckFubm91bmNlbWVudExpc3QoaXRlbXMpIHsKICBpZiAoIWl0ZW1zLmxlbmd0aCkgcmV0dXJuICc8cCBjbGFzcz0ibXV0ZWQiPk5vIGFubm91bmNlbWVudHMgeWV0LjwvcD4nOwogIHJldHVybiBpdGVtcwogICAgLm1hcCgKICAgICAgKGEpID0+IGA8ZGl2IHN0eWxlPSJtYXJnaW4tYm90dG9tOjE0cHg7Ij4KICAgICAgICA8c3Ryb25nPiR7ZXNjKGEudGl0bGUpfTwvc3Ryb25nPiA8c3BhbiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDsiPmJ5ICR7ZXNjKGEuY3JlYXRvcl9uYW1lKX0gJm1pZGRvdDsgJHtmbXREYXRlKGEuY3JlYXRlZF9hdCl9PC9zcGFuPgogICAgICAgIDxwIHN0eWxlPSJtYXJnaW46NHB4IDAgMDsiPiR7ZXNjKGEuYm9keSl9PC9wPgogICAgICA8L2Rpdj5gCiAgICApCiAgICAuam9pbignJyk7Cn0KCi8vIC0tLS0tLS0tLS0gS1BJcyAtLS0tLS0tLS0tCmZ1bmN0aW9uIHJlbmRlcktwaUxpc3Qoa3BpcykgewogIGlmICgha3Bpcy5sZW5ndGgpIHJldHVybiAnPHAgY2xhc3M9Im11dGVkIj5ObyBLUElzIHlldC48L3A+JzsKICByZXR1cm4ga3BpcwogICAgLm1hcCgoaykgPT4gewogICAgICBjb25zdCBwY3QgPSBrLnRhcmdldF92YWx1ZSA/IE1hdGgubWluKDEwMCwgTWF0aC5yb3VuZCgoay5jdXJyZW50X3ZhbHVlIC8gay50YXJnZXRfdmFsdWUpICogMTAwKSkgOiAwOwogICAgICBjb25zdCBjYW5FZGl0ID0gc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJyAmJiAoc3RhdGUudXNlci5yb2xlID09PSAndnAnIHx8IGsub3duZXJfaWQgPT09IHN0YXRlLnVzZXIuaWQpOwogICAgICByZXR1cm4gYDxkaXYgc3R5bGU9Im1hcmdpbi1ib3R0b206MTZweDsgcGFkZGluZy1ib3R0b206MTZweDsgYm9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTsiPgogICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDsganVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOmZsZXgtc3RhcnQ7Ij4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxzdHJvbmc+JHtlc2Moay50aXRsZSl9PC9zdHJvbmc+ICR7YmFkZ2Uoay5zdGF0dXMpfQogICAgICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4OyI+T3duZXI6ICR7ZXNjKGsub3duZXJfbmFtZSl9ICR7ay5wZXJpb2QgPyAnJm1pZGRvdDsgJyArIGVzYyhrLnBlcmlvZCkgOiAnJ308L2Rpdj4KICAgICAgICAgICAgJHtrLmRlc2NyaXB0aW9uID8gYDxwIHN0eWxlPSJtYXJnaW46NnB4IDAgMDsiPiR7ZXNjKGsuZGVzY3JpcHRpb24pfTwvcD5gIDogJyd9CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgc3R5bGU9InRleHQtYWxpZ246cmlnaHQ7IHdoaXRlLXNwYWNlOm5vd3JhcDsiPgogICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXdlaWdodDo3MDA7Ij4ke2VzYyhrLmN1cnJlbnRfdmFsdWUgPz8gMCl9JHtrLnRhcmdldF92YWx1ZSA/ICcgLyAnICsgZXNjKGsudGFyZ2V0X3ZhbHVlKSA6ICcnfSAke2VzYyhrLnVuaXQgfHwgJycpfTwvZGl2PgogICAgICAgICAgICAke2NhbkVkaXQgPyBgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSIgc3R5bGU9Im1hcmdpbi10b3A6NnB4OyIgb25jbGljaz0iZWRpdEtwaSgke2suaWR9KSI+VXBkYXRlPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgc3R5bGU9Im1hcmdpbi10b3A6NnB4OyIgb25jbGljaz0iZGVsZXRlS3BpKCR7ay5pZH0pIj5EZWxldGU8L2J1dHRvbj5gIDogJyd9CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICAke2sudGFyZ2V0X3ZhbHVlID8gYDxkaXYgY2xhc3M9InByb2dyZXNzIj48ZGl2IGNsYXNzPSJwcm9ncmVzcy1maWxsIiBzdHlsZT0id2lkdGg6JHtwY3R9JTsiPjwvZGl2PjwvZGl2PmAgOiAnJ30KICAgICAgPC9kaXY+YDsKICAgIH0pCiAgICAuam9pbignJyk7Cn0KCmFzeW5jIGZ1bmN0aW9uIHZpZXdLcGlzKHZpZXcpIHsKICBjb25zdCB7IGtwaXMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkva3BpcycpOwogIGNvbnN0IGNhbkNyZWF0ZSA9IHN0YXRlLnVzZXIucm9sZSAhPT0gJ3ZvbHVudGVlcic7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPiR7c3RhdGUudXNlci5yb2xlID09PSAndm9sdW50ZWVyJyA/ICdSZWFkLW9ubHkgdmlldyBvZiB5b3VyIHRlYW1cJ3MgS1BJcy4nIDogJ1RyYWNrIHByb2dyZXNzIGFnYWluc3QgdGFyZ2V0cy4nfTwvcD4KICAgICAgJHtjYW5DcmVhdGUgPyAnPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdLcGkoKSI+KyBOZXcgS1BJPC9idXR0b24+JyA6ICcnfQogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4ke3JlbmRlcktwaUxpc3Qoa3Bpcyl9PC9kaXY+CiAgYDsKfQoKYXN5bmMgZnVuY3Rpb24gbmV3S3BpKCkgewogIGxldCBvd25lck9wdGlvbnMgPSAnJzsKICBpZiAoc3RhdGUudXNlci5yb2xlID09PSAndnAnKSB7CiAgICBjb25zdCB7IHVzZXJzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3VzZXJzJyk7CiAgICBjb25zdCBtYW5hZ2VycyA9IHVzZXJzLmZpbHRlcigodSkgPT4gdS5yb2xlID09PSAnbWFuYWdlcicpOwogICAgb3duZXJPcHRpb25zID0gYDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+QXNzaWduIHRvIG1hbmFnZXI8L2xhYmVsPgogICAgICA8c2VsZWN0IGlkPSJrcGlPd25lciI+JHttYW5hZ2Vycy5tYXAoKG0pID0+IGA8b3B0aW9uIHZhbHVlPSIke20uaWR9Ij4ke2VzYyhtLm5hbWUpfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PgogICAgPC9kaXY+YDsKICB9CiAgb3Blbk1vZGFsKCdOZXcgS1BJJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UaXRsZTwvbGFiZWw+PGlucHV0IGlkPSJrcGlUaXRsZSIgcGxhY2Vob2xkZXI9ImUuZy4gVm9sdW50ZWVyIHJldGVudGlvbiByYXRlIiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5EZXNjcmlwdGlvbjwvbGFiZWw+PHRleHRhcmVhIGlkPSJrcGlEZXNjIj48L3RleHRhcmVhPjwvZGl2PgogICAgJHtvd25lck9wdGlvbnN9CiAgICA8ZGl2IGNsYXNzPSJ0d28tY29sIj4KICAgICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UYXJnZXQgdmFsdWU8L2xhYmVsPjxpbnB1dCBpZD0ia3BpVGFyZ2V0IiB0eXBlPSJudW1iZXIiIC8+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+Q3VycmVudCB2YWx1ZTwvbGFiZWw+PGlucHV0IGlkPSJrcGlDdXJyZW50IiB0eXBlPSJudW1iZXIiIHZhbHVlPSIwIiAvPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0d28tY29sIj4KICAgICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5Vbml0PC9sYWJlbD48aW5wdXQgaWQ9ImtwaVVuaXQiIHBsYWNlaG9sZGVyPSIlLCBob3VycywgcGVvcGxlLi4uIiAvPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlBlcmlvZDwvbGFiZWw+PGlucHV0IGlkPSJrcGlQZXJpb2QiIHBsYWNlaG9sZGVyPSJRMyAyMDI2IiAvPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0S3BpKCkiPkNyZWF0ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KCmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdEtwaSgpIHsKICBjb25zdCBvd25lclNlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlPd25lcicpOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9rcGlzJywgewogICAgICB0aXRsZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2twaVRpdGxlJykudmFsdWUsCiAgICAgIGRlc2NyaXB0aW9uOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpRGVzYycpLnZhbHVlLAogICAgICBvd25lcl9pZDogb3duZXJTZWwgPyBOdW1iZXIob3duZXJTZWwudmFsdWUpIDogdW5kZWZpbmVkLAogICAgICB0YXJnZXRfdmFsdWU6IE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpVGFyZ2V0JykudmFsdWUpIHx8IG51bGwsCiAgICAgIGN1cnJlbnRfdmFsdWU6IE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpQ3VycmVudCcpLnZhbHVlKSB8fCAwLAogICAgICB1bml0OiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpVW5pdCcpLnZhbHVlLAogICAgICBwZXJpb2Q6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlQZXJpb2QnKS52YWx1ZSwKICAgIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdLUEkgY3JlYXRlZCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KCmFzeW5jIGZ1bmN0aW9uIGVkaXRLcGkoaWQpIHsKICBjb25zdCB7IGtwaXMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkva3BpcycpOwogIGNvbnN0IGsgPSBrcGlzLmZpbmQoKHgpID0+IHguaWQgPT09IGlkKTsKICBvcGVuTW9kYWwoJ1VwZGF0ZSBLUEknLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkN1cnJlbnQgdmFsdWU8L2xhYmVsPjxpbnB1dCBpZD0ia3BpQ3VycmVudEVkaXQiIHR5cGU9Im51bWJlciIgdmFsdWU9IiR7ZXNjKGsuY3VycmVudF92YWx1ZSl9IiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5TdGF0dXM8L2xhYmVsPgogICAgICA8c2VsZWN0IGlkPSJrcGlTdGF0dXNFZGl0Ij4KICAgICAgICAke1snb25fdHJhY2snLCAnYXRfcmlzaycsICdvZmZfdHJhY2snXS5tYXAoKHMpID0+IGA8b3B0aW9uIHZhbHVlPSIke3N9IiAke2suc3RhdHVzID09PSBzID8gJ3NlbGVjdGVkJyA6ICcnfT4ke3MucmVwbGFjZSgnXycsICcgJyl9PC9vcHRpb24+YCkuam9pbignJyl9CiAgICAgIDwvc2VsZWN0PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0S3BpRWRpdCgke2lkfSkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9Cgphc3luYyBmdW5jdGlvbiBzdWJtaXRLcGlFZGl0KGlkKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUFVUJywgYC9hcGkva3Bpcy8ke2lkfWAsIHsKICAgICAgY3VycmVudF92YWx1ZTogTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdrcGlDdXJyZW50RWRpdCcpLnZhbHVlKSwKICAgICAgc3RhdHVzOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgna3BpU3RhdHVzRWRpdCcpLnZhbHVlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0tQSSB1cGRhdGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKYXN5bmMgZnVuY3Rpb24gZGVsZXRlS3BpKGlkKSB7CiAgaWYgKCFjb25maXJtKCdEZWxldGUgdGhpcyBLUEk/JykpIHJldHVybjsKICB0cnkgewogICAgYXdhaXQgYXBpKCdERUxFVEUnLCBgL2FwaS9rcGlzLyR7aWR9YCk7CiAgICBzaG93VG9hc3QoJ0tQSSBkZWxldGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBJZGVhcyAtLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIHZpZXdJZGVhcyh2aWV3KSB7CiAgY29uc3QgeyBpZGVhcyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9pZGVhcycpOwogIGNvbnN0IGNhbk1hbmFnZSA9IHN0YXRlLnVzZXIucm9sZSAhPT0gJ3ZvbHVudGVlcic7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPiR7Y2FuTWFuYWdlID8gJ0lkZWFzIHN1Ym1pdHRlZCBieSB5b3VyIHRlYW0uJyA6ICdJZGVhcyB5b3VcJ3ZlIHN1Ym1pdHRlZCwgYW5kIG1hbmFnZXIgcmVzcG9uc2VzLid9PC9wPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9Im5ld0lkZWEoKSI+KyBTdWJtaXQgaWRlYTwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPHRhYmxlPgogICAgICAgIDx0aGVhZD48dHI+PHRoPlRpdGxlPC90aD48dGg+U3VibWl0dGVkIGJ5PC90aD48dGg+U3RhdHVzPC90aD48dGg+UmVzcG9uc2U8L3RoPjx0aD48L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHk+CiAgICAgICAgICAke2lkZWFzLmxlbmd0aCA/IGlkZWFzLm1hcCgoaSkgPT4gYAogICAgICAgICAgICA8dHI+CiAgICAgICAgICAgICAgPHRkPjxzdHJvbmc+JHtlc2MoaS50aXRsZSl9PC9zdHJvbmc+PGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDsiPiR7ZXNjKGkuZGVzY3JpcHRpb24gfHwgJycpfTwvZGl2PjwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKGkuc3VibWl0dGVyX25hbWUpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7YmFkZ2UoaS5zdGF0dXMpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKGkucmVzcG9uc2UgfHwgJycpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7Y2FuTWFuYWdlID8gYDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20iIG9uY2xpY2s9InJlc3BvbmRJZGVhKCR7aS5pZH0sICcke2VzYyhpLnN0YXR1cyl9JykiPk1hbmFnZTwvYnV0dG9uPmAgOiAnJ308L3RkPgogICAgICAgICAgICA8L3RyPgogICAgICAgICAgYCkuam9pbignJykgOiAnPHRyIGNsYXNzPSJlbXB0eS1yb3ciPjx0ZCBjb2xzcGFuPSI1Ij5ObyBpZGVhcyB5ZXQuPC90ZD48L3RyPid9CiAgICAgICAgPC90Ym9keT4KICAgICAgPC90YWJsZT4KICAgIDwvZGl2PgogIGA7Cn0KCmZ1bmN0aW9uIG5ld0lkZWEoKSB7CiAgb3Blbk1vZGFsKCdTdWJtaXQgYW4gaWRlYScsIGAKICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+VGl0bGU8L2xhYmVsPjxpbnB1dCBpZD0iaWRlYVRpdGxlIiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5EZXRhaWxzPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImlkZWFEZXNjIj48L3RleHRhcmVhPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdElkZWEoKSI+U3VibWl0PC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQphc3luYyBmdW5jdGlvbiBzdWJtaXRJZGVhKCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9pZGVhcycsIHsgdGl0bGU6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdpZGVhVGl0bGUnKS52YWx1ZSwgZGVzY3JpcHRpb246IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdpZGVhRGVzYycpLnZhbHVlIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdJZGVhIHN1Ym1pdHRlZCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KCmZ1bmN0aW9uIHJlc3BvbmRJZGVhKGlkLCBjdXJyZW50U3RhdHVzKSB7CiAgY29uc3Qgc3RhdHVzZXMgPSBbJ25ldycsICdpbl9yZXZpZXcnLCAnYXBwcm92ZWQnLCAnaW1wbGVtZW50ZWQnLCAncmVqZWN0ZWQnXTsKICBvcGVuTW9kYWwoJ01hbmFnZSBpZGVhJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5TdGF0dXM8L2xhYmVsPgogICAgICA8c2VsZWN0IGlkPSJpZGVhU3RhdHVzIj4ke3N0YXR1c2VzLm1hcCgocykgPT4gYDxvcHRpb24gdmFsdWU9IiR7c30iICR7cyA9PT0gY3VycmVudFN0YXR1cyA/ICdzZWxlY3RlZCcgOiAnJ30+JHtzLnJlcGxhY2UoJ18nLCAnICcpfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlJlc3BvbnNlIHRvIHN1Ym1pdHRlcjwvbGFiZWw+PHRleHRhcmVhIGlkPSJpZGVhUmVzcG9uc2UiPjwvdGV4dGFyZWE+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0SWRlYVJlc3BvbnNlKCR7aWR9KSI+U2F2ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0SWRlYVJlc3BvbnNlKGlkKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUFVUJywgYC9hcGkvaWRlYXMvJHtpZH1gLCB7IHN0YXR1czogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2lkZWFTdGF0dXMnKS52YWx1ZSwgcmVzcG9uc2U6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdpZGVhUmVzcG9uc2UnKS52YWx1ZSB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnSWRlYSB1cGRhdGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBDb21wbGFpbnRzIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld0NvbXBsYWludHModmlldykgewogIGNvbnN0IHsgY29tcGxhaW50cyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9jb21wbGFpbnRzJyk7CiAgY29uc3QgY2FuTWFuYWdlID0gc3RhdGUudXNlci5yb2xlICE9PSAndm9sdW50ZWVyJzsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+JHtjYW5NYW5hZ2UgPyAnQ29tcGxhaW50cyByYWlzZWQgYnkgeW91ciB0ZWFtLicgOiAnQ29tcGxhaW50cy9wcm9ibGVtcyB5b3VcJ3ZlIHJhaXNlZC4nfTwvcD4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdDb21wbGFpbnQoKSI+KyBSZXBvcnQgYSBwcm9ibGVtPC9idXR0b24+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8dGFibGU+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+VGl0bGU8L3RoPjx0aD5TdWJtaXR0ZWQgYnk8L3RoPjx0aD5TdGF0dXM8L3RoPjx0aD5SZXNvbHV0aW9uPC90aD48dGg+PC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5PgogICAgICAgICAgJHtjb21wbGFpbnRzLmxlbmd0aCA/IGNvbXBsYWludHMubWFwKChjKSA9PiBgCiAgICAgICAgICAgIDx0cj4KICAgICAgICAgICAgICA8dGQ+PHN0cm9uZz4ke2VzYyhjLnRpdGxlKX08L3N0cm9uZz48ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4OyI+JHtlc2MoYy5kZXNjcmlwdGlvbiB8fCAnJyl9PC9kaXY+PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoYy5zdWJtaXR0ZXJfbmFtZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtiYWRnZShjLnN0YXR1cyl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoYy5yZXNvbHV0aW9uX25vdGVzIHx8ICcnKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2Nhbk1hbmFnZSA/IGA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIiBvbmNsaWNrPSJyZXNvbHZlQ29tcGxhaW50KCR7Yy5pZH0sICcke2VzYyhjLnN0YXR1cyl9JykiPk1hbmFnZTwvYnV0dG9uPmAgOiAnJ308L3RkPgogICAgICAgICAgICA8L3RyPgogICAgICAgICAgYCkuam9pbignJykgOiAnPHRyIGNsYXNzPSJlbXB0eS1yb3ciPjx0ZCBjb2xzcGFuPSI1Ij5Ob3RoaW5nIHJlcG9ydGVkIHlldC48L3RkPjwvdHI+J30KICAgICAgICA8L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+CiAgYDsKfQpmdW5jdGlvbiBuZXdDb21wbGFpbnQoKSB7CiAgb3Blbk1vZGFsKCdSZXBvcnQgYSBwcm9ibGVtJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UaXRsZTwvbGFiZWw+PGlucHV0IGlkPSJjVGl0bGUiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkRldGFpbHM8L2xhYmVsPjx0ZXh0YXJlYSBpZD0iY0Rlc2MiPjwvdGV4dGFyZWE+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0Q29tcGxhaW50KCkiPlN1Ym1pdDwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0Q29tcGxhaW50KCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9jb21wbGFpbnRzJywgeyB0aXRsZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NUaXRsZScpLnZhbHVlLCBkZXNjcmlwdGlvbjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NEZXNjJykudmFsdWUgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1JlcG9ydGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQpmdW5jdGlvbiByZXNvbHZlQ29tcGxhaW50KGlkLCBjdXJyZW50U3RhdHVzKSB7CiAgY29uc3Qgc3RhdHVzZXMgPSBbJ29wZW4nLCAnaW5fcHJvZ3Jlc3MnLCAncmVzb2x2ZWQnXTsKICBvcGVuTW9kYWwoJ01hbmFnZSBjb21wbGFpbnQnLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlN0YXR1czwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9ImNTdGF0dXMiPiR7c3RhdHVzZXMubWFwKChzKSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHtzfSIgJHtzID09PSBjdXJyZW50U3RhdHVzID8gJ3NlbGVjdGVkJyA6ICcnfT4ke3MucmVwbGFjZSgnXycsICcgJyl9PC9vcHRpb24+YCkuam9pbignJyl9PC9zZWxlY3Q+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+UmVzb2x1dGlvbiBub3RlczwvbGFiZWw+PHRleHRhcmVhIGlkPSJjTm90ZXMiPjwvdGV4dGFyZWE+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0Q29tcGxhaW50UmVzb2x2ZSgke2lkfSkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdENvbXBsYWludFJlc29sdmUoaWQpIHsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQVVQnLCBgL2FwaS9jb21wbGFpbnRzLyR7aWR9YCwgeyBzdGF0dXM6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjU3RhdHVzJykudmFsdWUsIHJlc29sdXRpb25fbm90ZXM6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjTm90ZXMnKS52YWx1ZSB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnVXBkYXRlZCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KCi8vIC0tLS0tLS0tLS0gUmVwb3J0cyAobWFuYWdlciAtPiBWUCkgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3UmVwb3J0cyh2aWV3KSB7CiAgY29uc3QgeyByZXBvcnRzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3JlcG9ydHMnKTsKICBjb25zdCBpc1ZwID0gc3RhdGUudXNlci5yb2xlID09PSAndnAnOwogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10b29sYmFyIj4KICAgICAgPHAgY2xhc3M9Im11dGVkIj4ke2lzVnAgPyAnUmVwb3J0cyBzdWJtaXR0ZWQgYnkgeW91ciBtYW5hZ2Vycy4nIDogJ1NlbmQgYSBzdW1tYXJ5IG9mIHByb2JsZW1zLCBpZGVhcyBhbmQgS1BJIHByb2dyZXNzIHRvIHRoZSBWUC4nfTwvcD4KICAgICAgJHshaXNWcCA/ICc8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9Im5ld1JlcG9ydCgpIj4rIE5ldyByZXBvcnQ8L2J1dHRvbj4nIDogJyd9CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8dGFibGU+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+TWFuYWdlcjwvdGg+PHRoPlBlcmlvZDwvdGg+PHRoPlN1bW1hcnk8L3RoPjx0aD5TdGF0dXM8L3RoPiR7aXNWcCA/ICc8dGg+VlAgbm90ZXM8L3RoPjx0aD48L3RoPicgOiAnJ308L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5PgogICAgICAgICAgJHtyZXBvcnRzLmxlbmd0aCA/IHJlcG9ydHMubWFwKChyKSA9PiBgCiAgICAgICAgICAgIDx0cj4KICAgICAgICAgICAgICA8dGQ+JHtlc2Moci5tYW5hZ2VyX25hbWUpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKHIucGVyaW9kIHx8ICcnKX08L3RkPgogICAgICAgICAgICAgIDx0ZCBzdHlsZT0ibWF4LXdpZHRoOjI4MHB4OyI+JHtlc2Moci5zdW1tYXJ5KX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2JhZGdlKHIuc3RhdHVzKX08L3RkPgogICAgICAgICAgICAgICR7aXNWcCA/IGA8dGQ+JHtlc2Moci52cF9ub3RlcyB8fCAnJyl9PC90ZD48dGQ+PGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSIgb25jbGljaz0icmV2aWV3UmVwb3J0KCR7ci5pZH0sICcke2VzYyhyLnN0YXR1cyl9JykiPlJldmlldzwvYnV0dG9uPjwvdGQ+YCA6ICcnfQogICAgICAgICAgICA8L3RyPgogICAgICAgICAgYCkuam9pbignJykgOiBgPHRyIGNsYXNzPSJlbXB0eS1yb3ciPjx0ZCBjb2xzcGFuPSIke2lzVnAgPyA2IDogNH0iPk5vIHJlcG9ydHMgeWV0LjwvdGQ+PC90cj5gfQogICAgICAgIDwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj4KICBgOwp9CmFzeW5jIGZ1bmN0aW9uIG5ld1JlcG9ydCgpIHsKICBjb25zdCBzbmFwID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9yZXBvcnRzL3NuYXBzaG90Jyk7CiAgb3Blbk1vZGFsKCdOZXcgcmVwb3J0IHRvIFZQJywgYAogICAgPHAgY2xhc3M9InNtYWxsLW5vdGUiPkN1cnJlbnQgc25hcHNob3Q6ICR7c25hcC5vcGVuQ29tcGxhaW50c30gb3BlbiBjb21wbGFpbnQocyksICR7c25hcC5uZXdJZGVhc30gbmV3IGlkZWEocyksICR7c25hcC5rcGlDb3VudH0gS1BJKHMpIHRyYWNrZWQuPC9wPgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5QZXJpb2Q8L2xhYmVsPjxpbnB1dCBpZD0icmVwUGVyaW9kIiBwbGFjZWhvbGRlcj0iUTMgMjAyNiwgb3IgSnVseSAyMDI2IiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5TdW1tYXJ5IGZvciB0aGUgVlA8L2xhYmVsPjx0ZXh0YXJlYSBpZD0icmVwU3VtbWFyeSIgcGxhY2Vob2xkZXI9IktleSB3aW5zLCBwcm9ibGVtcywgaWRlYXMsIGFuZCBLUEkgc3RhdHVzIHRoaXMgcGVyaW9kLi4uIj48L3RleHRhcmVhPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdFJlcG9ydCgpIj5TZW5kIHRvIFZQPC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQphc3luYyBmdW5jdGlvbiBzdWJtaXRSZXBvcnQoKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL3JlcG9ydHMnLCB7IHBlcmlvZDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlcFBlcmlvZCcpLnZhbHVlLCBzdW1tYXJ5OiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVwU3VtbWFyeScpLnZhbHVlIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdSZXBvcnQgc2VudCB0byBWUCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KZnVuY3Rpb24gcmV2aWV3UmVwb3J0KGlkLCBjdXJyZW50U3RhdHVzKSB7CiAgb3Blbk1vZGFsKCdSZXZpZXcgcmVwb3J0JywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5TdGF0dXM8L2xhYmVsPgogICAgICA8c2VsZWN0IGlkPSJyZXBTdGF0dXMiPgogICAgICAgICR7WydzdWJtaXR0ZWQnLCAncmV2aWV3ZWQnXS5tYXAoKHMpID0+IGA8b3B0aW9uIHZhbHVlPSIke3N9IiAke3MgPT09IGN1cnJlbnRTdGF0dXMgPyAnc2VsZWN0ZWQnIDogJyd9PiR7c308L29wdGlvbj5gKS5qb2luKCcnKX0KICAgICAgPC9zZWxlY3Q+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+Tm90ZXMgYmFjayB0byBtYW5hZ2VyPC9sYWJlbD48dGV4dGFyZWEgaWQ9InJlcE5vdGVzIj48L3RleHRhcmVhPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdFJlcG9ydFJldmlldygke2lkfSkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdFJlcG9ydFJldmlldyhpZCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BVVCcsIGAvYXBpL3JlcG9ydHMvJHtpZH1gLCB7IHN0YXR1czogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlcFN0YXR1cycpLnZhbHVlLCB2cF9ub3RlczogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlcE5vdGVzJykudmFsdWUgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1NhdmVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBIb3VycyAmIGF0dGVuZGFuY2UgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3SG91cnModmlldykgewogIGNvbnN0IHsgaG91cnMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvaG91cnMnKTsKICB2aWV3LmlubmVySFRNTCA9IGAKICAgIDxkaXYgY2xhc3M9InNlY3Rpb24tdG9vbGJhciI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+TG9nIHZvbHVudGVlciBob3VycyBhbmQgZXhwb3J0IHRoZW0gZm9yIHJlcG9ydGluZy48L3A+CiAgICAgIDxkaXY+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJleHBvcnRIb3Vyc0NzdigpIj5FeHBvcnQgQ1NWPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdIb3Vyc0xvZygpIj4rIExvZyBob3VyczwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDx0YWJsZT4KICAgICAgICA8dGhlYWQ+PHRyPjx0aD5EYXRlPC90aD48dGg+Vm9sdW50ZWVyPC90aD48dGg+SG91cnM8L3RoPjx0aD5Ob3RlPC90aD48dGg+PC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5PgogICAgICAgICAgJHtob3Vycy5sZW5ndGggPyBob3Vycy5tYXAoKGgpID0+IGAKICAgICAgICAgICAgPHRyPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhoLndvcmtfZGF0ZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoaC52b2x1bnRlZXJfbmFtZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoaC5ob3Vycyl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtlc2MoaC5ub3RlIHx8ICcnKX08L3RkPgogICAgICAgICAgICAgIDx0ZD48YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1kYW5nZXIiIG9uY2xpY2s9ImRlbGV0ZUhvdXJzTG9nKCR7aC5pZH0pIj5EZWxldGU8L2J1dHRvbj48L3RkPgogICAgICAgICAgICA8L3RyPgogICAgICAgICAgYCkuam9pbignJykgOiAnPHRyIGNsYXNzPSJlbXB0eS1yb3ciPjx0ZCBjb2xzcGFuPSI1Ij5ObyBob3VycyBsb2dnZWQgeWV0LjwvdGQ+PC90cj4nfQogICAgICAgIDwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj4KICBgOwp9CmFzeW5jIGZ1bmN0aW9uIG5ld0hvdXJzTG9nKCkgewogIGNvbnN0IHsgdXNlcnMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvdXNlcnMnKTsKICBjb25zdCB2b2x1bnRlZXJzID0gdXNlcnMuZmlsdGVyKCh1KSA9PiB1LnJvbGUgPT09ICd2b2x1bnRlZXInICYmIHUuYWN0aXZlKTsKICBpZiAoIXZvbHVudGVlcnMubGVuZ3RoKSB7CiAgICBvcGVuTW9kYWwoJ0xvZyBob3VycycsIGA8cCBjbGFzcz0ibXV0ZWQiPk5vIHZvbHVudGVlcnMgYXZhaWxhYmxlIHlldC48L3A+PGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj48YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2xvc2U8L2J1dHRvbj48L2Rpdj5gKTsKICAgIHJldHVybjsKICB9CiAgY29uc3QgdG9kYXkgPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogIG9wZW5Nb2RhbCgnTG9nIGhvdXJzJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5Wb2x1bnRlZXI8L2xhYmVsPgogICAgICA8c2VsZWN0IGlkPSJoVm9sdW50ZWVyIj4ke3ZvbHVudGVlcnMubWFwKCh2KSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHt2LmlkfSI+JHtlc2Modi5uYW1lKX08L29wdGlvbj5gKS5qb2luKCcnKX08L3NlbGVjdD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0idHdvLWNvbCI+CiAgICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RGF0ZTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJoRGF0ZSIgdmFsdWU9IiR7dG9kYXl9IiAvPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkhvdXJzPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBzdGVwPSIwLjUiIG1pbj0iMCIgaWQ9ImhIb3VycyIgLz48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5Ob3RlIChvcHRpb25hbCk8L2xhYmVsPjxpbnB1dCBpZD0iaE5vdGUiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0SG91cnNMb2coKSI+U2F2ZTwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0SG91cnNMb2coKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2hvdXJzJywgewogICAgICB2b2x1bnRlZXJfaWQ6IE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaFZvbHVudGVlcicpLnZhbHVlKSwKICAgICAgd29ya19kYXRlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaERhdGUnKS52YWx1ZSwKICAgICAgaG91cnM6IE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaEhvdXJzJykudmFsdWUpLAogICAgICBub3RlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaE5vdGUnKS52YWx1ZSwKICAgIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdIb3VycyBsb2dnZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUhvdXJzTG9nKGlkKSB7CiAgaWYgKCFjb25maXJtKCdEZWxldGUgdGhpcyBob3VycyBlbnRyeT8nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL2hvdXJzLyR7aWR9YCk7CiAgICBzaG93VG9hc3QoJ0RlbGV0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGV4cG9ydEhvdXJzQ3N2KCkgewogIHRyeSB7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgnL2FwaS9ob3Vycy9leHBvcnQnLCB7IGhlYWRlcnM6IHsgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgc3RhdGUudG9rZW4gfSB9KTsKICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoJ0V4cG9ydCBmYWlsZWQnKTsKICAgIGNvbnN0IGJsb2IgPSBhd2FpdCByZXMuYmxvYigpOwogICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgIGNvbnN0IGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7CiAgICBhLmhyZWYgPSB1cmw7IGEuZG93bmxvYWQgPSAndm9sdW50ZWVyLWhvdXJzLmNzdic7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOyBhLmNsaWNrKCk7IGEucmVtb3ZlKCk7CiAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBTaGlmdCBzY2hlZHVsaW5nIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld1NoaWZ0cyh2aWV3KSB7CiAgY29uc3QgeyBzaGlmdHMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvc2hpZnRzJyk7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPkNyZWF0ZSBzaGlmdHMvZXZlbnRzIGFuZCBhc3NpZ24gdm9sdW50ZWVycyB0byB0aGVtLjwvcD4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdTaGlmdCgpIj4rIE5ldyBzaGlmdDwvYnV0dG9uPgogICAgPC9kaXY+CiAgICAke3NoaWZ0cy5sZW5ndGggPyBzaGlmdHMubWFwKChzKSA9PiBgCiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxoMyBzdHlsZT0ibWFyZ2luLWJvdHRvbToycHg7Ij4ke2VzYyhzLnRpdGxlKX08L2gzPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxM3B4OyI+JHtlc2Mocy5zaGlmdF9kYXRlKX0gJHtzLnN0YXJ0X3RpbWUgPyBlc2Mocy5zdGFydF90aW1lKSArICcmbmRhc2g7JyArIGVzYyhzLmVuZF90aW1lIHx8ICcnKSA6ICcnfSAke3MubG9jYXRpb24gPyAnJm1pZGRvdDsgJyArIGVzYyhzLmxvY2F0aW9uKSA6ICcnfTwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIiBvbmNsaWNrPSJhc3NpZ25Ub1NoaWZ0KCR7cy5pZH0pIj5Bc3NpZ24gdm9sdW50ZWVyPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgb25jbGljaz0iZGVsZXRlU2hpZnQoJHtzLmlkfSkiPkRlbGV0ZTwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgJHtzLm5vdGVzID8gYDxwIGNsYXNzPSJzbWFsbC1ub3RlIj4ke2VzYyhzLm5vdGVzKX08L3A+YCA6ICcnfQogICAgICAgIDxkaXY+CiAgICAgICAgICAke3MuYXNzaWdubWVudHMubGVuZ3RoID8gcy5hc3NpZ25tZW50cy5tYXAoKGEpID0+IGAKICAgICAgICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIGJhZGdlLXN1Ym1pdHRlZCIgc3R5bGU9Im1hcmdpbjowIDZweCA2cHggMDsgZGlzcGxheTppbmxpbmUtZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBnYXA6NnB4OyI+CiAgICAgICAgICAgICAgJHtlc2MoYS52b2x1bnRlZXJfbmFtZSl9CiAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLWljb24iIHN0eWxlPSJmb250LXNpemU6MTRweDsgY29sb3I6aW5oZXJpdDsiIG9uY2xpY2s9InVuYXNzaWduU2hpZnQoJHthLmlkfSkiIHRpdGxlPSJSZW1vdmUiPiZ0aW1lczs8L2J1dHRvbj4KICAgICAgICAgICAgPC9zcGFuPgogICAgICAgICAgYCkuam9pbignJykgOiAnPHNwYW4gY2xhc3M9Im11dGVkIj5ObyB2b2x1bnRlZXJzIGFzc2lnbmVkIHlldC48L3NwYW4+J30KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICBgKS5qb2luKCcnKSA6ICc8ZGl2IGNsYXNzPSJjYXJkIj48cCBjbGFzcz0ibXV0ZWQiPk5vIHNoaWZ0cyBzY2hlZHVsZWQgeWV0LjwvcD48L2Rpdj4nfQogIGA7Cn0KZnVuY3Rpb24gbmV3U2hpZnQoKSB7CiAgb3Blbk1vZGFsKCdOZXcgc2hpZnQnLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlRpdGxlPC9sYWJlbD48aW5wdXQgaWQ9InNUaXRsZSIgcGxhY2Vob2xkZXI9ImUuZy4gSGVhbHRoIGF3YXJlbmVzcyBib290aCIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InR3by1jb2wiPgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkRhdGU8L2xhYmVsPjxpbnB1dCB0eXBlPSJkYXRlIiBpZD0ic0RhdGUiIC8+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+TG9jYXRpb248L2xhYmVsPjxpbnB1dCBpZD0ic0xvY2F0aW9uIiAvPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0d28tY29sIj4KICAgICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5TdGFydCB0aW1lPC9sYWJlbD48aW5wdXQgdHlwZT0idGltZSIgaWQ9InNTdGFydCIgLz48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5FbmQgdGltZTwvbGFiZWw+PGlucHV0IHR5cGU9InRpbWUiIGlkPSJzRW5kIiAvPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPk5vdGVzPC9sYWJlbD48dGV4dGFyZWEgaWQ9InNOb3RlcyI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRTaGlmdCgpIj5DcmVhdGU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdFNoaWZ0KCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9zaGlmdHMnLCB7CiAgICAgIHRpdGxlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc1RpdGxlJykudmFsdWUsCiAgICAgIHNoaWZ0X2RhdGU6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzRGF0ZScpLnZhbHVlLAogICAgICBsb2NhdGlvbjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NMb2NhdGlvbicpLnZhbHVlLAogICAgICBzdGFydF90aW1lOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc1N0YXJ0JykudmFsdWUsCiAgICAgIGVuZF90aW1lOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc0VuZCcpLnZhbHVlLAogICAgICBub3RlczogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NOb3RlcycpLnZhbHVlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1NoaWZ0IGNyZWF0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVNoaWZ0KGlkKSB7CiAgaWYgKCFjb25maXJtKCdEZWxldGUgdGhpcyBzaGlmdD8nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL3NoaWZ0cy8ke2lkfWApOwogICAgc2hvd1RvYXN0KCdEZWxldGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQphc3luYyBmdW5jdGlvbiBhc3NpZ25Ub1NoaWZ0KHNoaWZ0SWQpIHsKICBjb25zdCB7IHVzZXJzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3VzZXJzJyk7CiAgY29uc3Qgdm9sdW50ZWVycyA9IHVzZXJzLmZpbHRlcigodSkgPT4gdS5yb2xlID09PSAndm9sdW50ZWVyJyAmJiB1LmFjdGl2ZSk7CiAgaWYgKCF2b2x1bnRlZXJzLmxlbmd0aCkgewogICAgb3Blbk1vZGFsKCdBc3NpZ24gdm9sdW50ZWVyJywgYDxwIGNsYXNzPSJtdXRlZCI+Tm8gdm9sdW50ZWVycyBhdmFpbGFibGUgeWV0LjwvcD48ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPjxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DbG9zZTwvYnV0dG9uPjwvZGl2PmApOwogICAgcmV0dXJuOwogIH0KICBvcGVuTW9kYWwoJ0Fzc2lnbiB2b2x1bnRlZXInLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlZvbHVudGVlcjwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9ImFzVm9sdW50ZWVyIj4ke3ZvbHVudGVlcnMubWFwKCh2KSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHt2LmlkfSI+JHtlc2Modi5uYW1lKX08L29wdGlvbj5gKS5qb2luKCcnKX08L3NlbGVjdD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdEFzc2lnblNoaWZ0KCR7c2hpZnRJZH0pIj5Bc3NpZ248L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdEFzc2lnblNoaWZ0KHNoaWZ0SWQpIHsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQT1NUJywgYC9hcGkvc2hpZnRzLyR7c2hpZnRJZH0vYXNzaWdubWVudHNgLCB7IHZvbHVudGVlcl9pZDogTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhc1ZvbHVudGVlcicpLnZhbHVlKSB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnQXNzaWduZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIHVuYXNzaWduU2hpZnQoYXNzaWdubWVudElkKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnREVMRVRFJywgYC9hcGkvc2hpZnQtYXNzaWdubWVudHMvJHthc3NpZ25tZW50SWR9YCk7CiAgICBzaG93VG9hc3QoJ1JlbW92ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIE1lc3NhZ2VzIC0tLS0tLS0tLS0KbGV0IG1zZ1NlbGVjdGVkQ29udGFjdCA9IG51bGw7CmFzeW5jIGZ1bmN0aW9uIHZpZXdNZXNzYWdlcyh2aWV3KSB7CiAgY29uc3QgeyBjb250YWN0cyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9tZXNzYWdlcy9jb250YWN0cycpOwogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0ibXNnLWxheW91dCI+CiAgICAgIDxkaXYgY2xhc3M9Im1zZy1jb250YWN0cyIgaWQ9Im1zZ0NvbnRhY3RzIj4KICAgICAgICAke2NvbnRhY3RzLmxlbmd0aCA/IGNvbnRhY3RzLm1hcCgoYykgPT4gYAogICAgICAgICAgPGRpdiBjbGFzcz0ibXNnLWNvbnRhY3QiIGRhdGEtaWQ9IiR7Yy5pZH0iIGRhdGEtbmFtZT0iJHtlc2MoYy5uYW1lKX0iPiR7ZXNjKGMubmFtZSl9PGRpdiBjbGFzcz0ibXV0ZWQtcm9sZSI+JHtlc2MoYy5yb2xlKX08L2Rpdj48L2Rpdj4KICAgICAgICBgKS5qb2luKCcnKSA6ICc8cCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJwYWRkaW5nOjEwcHg7Ij5ObyBjb250YWN0cyB5ZXQuPC9wPid9CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtc2ctdGhyZWFkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJtc2ctc2Nyb2xsIiBpZD0ibXNnU2Nyb2xsIj48cCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJwYWRkaW5nOjEwcHg7Ij5TZWxlY3QgYSBjb250YWN0IHRvIHN0YXJ0IG1lc3NhZ2luZy48L3A+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ibXNnLWNvbXBvc2UiPgogICAgICAgICAgPHRleHRhcmVhIGlkPSJtc2dJbnB1dCIgcGxhY2Vob2xkZXI9IldyaXRlIGEgbWVzc2FnZS4uLiIgZGlzYWJsZWQ+PC90ZXh0YXJlYT4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgaWQ9Im1zZ1NlbmRCdG4iIG9uY2xpY2s9InNlbmRNZXNzYWdlKCkiIGRpc2FibGVkPlNlbmQ8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICBgOwogIHZpZXcucXVlcnlTZWxlY3RvckFsbCgnLm1zZy1jb250YWN0JykuZm9yRWFjaCgoZWwpID0+IHsKICAgIGVsLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gb3BlblRocmVhZChOdW1iZXIoZWwuZGF0YXNldC5pZCksIGVsKSk7CiAgfSk7CiAgaWYgKG1zZ1NlbGVjdGVkQ29udGFjdCAmJiBjb250YWN0cy5zb21lKChjKSA9PiBjLmlkID09PSBtc2dTZWxlY3RlZENvbnRhY3QpKSB7CiAgICBjb25zdCBlbCA9IHZpZXcucXVlcnlTZWxlY3RvcihgLm1zZy1jb250YWN0W2RhdGEtaWQ9IiR7bXNnU2VsZWN0ZWRDb250YWN0fSJdYCk7CiAgICBpZiAoZWwpIG9wZW5UaHJlYWQobXNnU2VsZWN0ZWRDb250YWN0LCBlbCk7CiAgfQp9CmFzeW5jIGZ1bmN0aW9uIG9wZW5UaHJlYWQoY29udGFjdElkLCBlbCkgewogIG1zZ1NlbGVjdGVkQ29udGFjdCA9IGNvbnRhY3RJZDsKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcubXNnLWNvbnRhY3QnKS5mb3JFYWNoKChjKSA9PiBjLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpKTsKICBpZiAoZWwpIGVsLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtc2dJbnB1dCcpLmRpc2FibGVkID0gZmFsc2U7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21zZ1NlbmRCdG4nKS5kaXNhYmxlZCA9IGZhbHNlOwogIGNvbnN0IHsgbWVzc2FnZXMgfSA9IGF3YWl0IGFwaSgnR0VUJywgYC9hcGkvbWVzc2FnZXMvd2l0aC8ke2NvbnRhY3RJZH1gKTsKICBjb25zdCBzY3JvbGwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbXNnU2Nyb2xsJyk7CiAgY29uc3QgY29udGFjdE5hbWUgPSBlbCA/IGVsLmRhdGFzZXQubmFtZSA6ICcnOwogIHNjcm9sbC5pbm5lckhUTUwgPSBtZXNzYWdlcy5sZW5ndGggPyBtZXNzYWdlcy5tYXAoKG0pID0+IGAKICAgIDxkaXYgY2xhc3M9Im1zZy1idWJibGUgJHttLmZyb21fdXNlciA9PT0gc3RhdGUudXNlci5pZCA/ICdtaW5lJyA6ICcnfSI+CiAgICAgIDxkaXYgY2xhc3M9Im1zZy1zZW5kZXIiPiR7bS5mcm9tX3VzZXIgPT09IHN0YXRlLnVzZXIuaWQgPyAnWW91JyA6IGVzYyhjb250YWN0TmFtZSl9PC9kaXY+CiAgICAgICR7ZXNjKG0uYm9keSl9CiAgICAgIDxkaXYgY2xhc3M9Im1zZy10aW1lIj4ke2ZtdERhdGUobS5jcmVhdGVkX2F0KX08L2Rpdj4KICAgIDwvZGl2PgogIGApLmpvaW4oJycpIDogJzxwIGNsYXNzPSJtdXRlZCI+Tm8gbWVzc2FnZXMgeWV0LiBTYXkgaGVsbG8hPC9wPic7CiAgc2Nyb2xsLnNjcm9sbFRvcCA9IHNjcm9sbC5zY3JvbGxIZWlnaHQ7Cn0KYXN5bmMgZnVuY3Rpb24gc2VuZE1lc3NhZ2UoKSB7CiAgaWYgKCFtc2dTZWxlY3RlZENvbnRhY3QpIHJldHVybjsKICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtc2dJbnB1dCcpOwogIGNvbnN0IGJvZHkgPSBpbnB1dC52YWx1ZS50cmltKCk7CiAgaWYgKCFib2R5KSByZXR1cm47CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL21lc3NhZ2VzJywgeyB0b191c2VyOiBtc2dTZWxlY3RlZENvbnRhY3QsIGJvZHkgfSk7CiAgICBpbnB1dC52YWx1ZSA9ICcnOwogICAgY29uc3QgYWN0aXZlRWwgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcubXNnLWNvbnRhY3QuYWN0aXZlJyk7CiAgICBhd2FpdCBvcGVuVGhyZWFkKG1zZ1NlbGVjdGVkQ29udGFjdCwgYWN0aXZlRWwpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KCi8vIC0tLS0tLS0tLS0gRmlsZXMgKEV4Y2VsL0NTVikgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3RmlsZXModmlldykgewogIGNvbnN0IHsgZmlsZXMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvZmlsZXMnKTsKICBjb25zdCBjYW5VcGxvYWQgPSBzdGF0ZS51c2VyLnJvbGUgIT09ICd2b2x1bnRlZXInOwogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10b29sYmFyIj4KICAgICAgPHAgY2xhc3M9Im11dGVkIj5TaGFyZSBzcHJlYWRzaGVldHMgKHJvc3RlcnMsIGhvdXJzLCBLUEkgdHJhY2tlcnMpIHdpdGggeW91ciB0ZWFtLjwvcD4KICAgICAgJHtjYW5VcGxvYWQgPyAnPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdGaWxlKCkiPisgVXBsb2FkIGZpbGU8L2J1dHRvbj4nIDogJyd9CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8dGFibGU+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+RmlsZTwvdGg+PHRoPkRlc2NyaXB0aW9uPC90aD48dGg+VXBsb2FkZWQgYnk8L3RoPjx0aD5EYXRlPC90aD48dGg+PC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5PgogICAgICAgICAgJHtmaWxlcy5sZW5ndGggPyBmaWxlcy5tYXAoKGYpID0+IGAKICAgICAgICAgICAgPHRyPgogICAgICAgICAgICAgIDx0ZD48c3Ryb25nPiR7ZXNjKGYuZmlsZW5hbWUpfTwvc3Ryb25nPjwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKGYuZGVzY3JpcHRpb24gfHwgJycpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKGYudXBsb2FkZXJfbmFtZSl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHtmbXREYXRlKGYuY3JlYXRlZF9hdCl9PC90ZD4KICAgICAgICAgICAgICA8dGQ+CiAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIiBvbmNsaWNrPSJwcmV2aWV3RmlsZSgke2YuaWR9LCAnJHtlc2MoZi5maWxlbmFtZSl9JykiPlByZXZpZXc8L2J1dHRvbj4KICAgICAgICAgICAgICAgIDxhIGNsYXNzPSJidG4gYnRuLXNtIiBocmVmPSIvYXBpL2ZpbGVzLyR7Zi5pZH0vZG93bmxvYWQ/dD0ke2VuY29kZVVSSUNvbXBvbmVudChzdGF0ZS50b2tlbil9IiBvbmNsaWNrPSJyZXR1cm4gZG93bmxvYWRGaWxlKGV2ZW50LCAke2YuaWR9LCAnJHtlc2MoZi5maWxlbmFtZSl9JykiPkRvd25sb2FkPC9hPgogICAgICAgICAgICAgICAgJHtjYW5VcGxvYWQgPyBgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tZGFuZ2VyIiBvbmNsaWNrPSJkZWxldGVGaWxlKCR7Zi5pZH0pIj5EZWxldGU8L2J1dHRvbj5gIDogJyd9CiAgICAgICAgICAgICAgPC90ZD4KICAgICAgICAgICAgPC90cj4KICAgICAgICAgIGApLmpvaW4oJycpIDogJzx0ciBjbGFzcz0iZW1wdHktcm93Ij48dGQgY29sc3Bhbj0iNSI+Tm8gZmlsZXMgdXBsb2FkZWQgeWV0LjwvdGQ+PC90cj4nfQogICAgICAgIDwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj4KICBgOwp9CgpmdW5jdGlvbiBuZXdGaWxlKCkgewogIG9wZW5Nb2RhbCgnVXBsb2FkIGEgc3ByZWFkc2hlZXQnLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkZpbGUgKC5jc3YsIC50c3YsIC54bHMsIC54bHN4KTwvbGFiZWw+PGlucHV0IHR5cGU9ImZpbGUiIGlkPSJmaWxlSW5wdXQiIGFjY2VwdD0iLmNzdiwudHN2LC54bHMsLnhsc3giIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkRlc2NyaXB0aW9uPC9sYWJlbD48aW5wdXQgaWQ9ImZpbGVEZXNjIiBwbGFjZWhvbGRlcj0iZS5nLiBKdWx5IHZvbHVudGVlciBob3VycyIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRGaWxlKCkiPlVwbG9hZDwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KZnVuY3Rpb24gcmVhZEZpbGVBc0Jhc2U2NChmaWxlKSB7CiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHsKICAgIGNvbnN0IHJlYWRlciA9IG5ldyBGaWxlUmVhZGVyKCk7CiAgICByZWFkZXIub25sb2FkID0gKCkgPT4gcmVzb2x2ZShyZWFkZXIucmVzdWx0LnNwbGl0KCcsJylbMV0pOwogICAgcmVhZGVyLm9uZXJyb3IgPSByZWplY3Q7CiAgICByZWFkZXIucmVhZEFzRGF0YVVSTChmaWxlKTsKICB9KTsKfQphc3luYyBmdW5jdGlvbiBzdWJtaXRGaWxlKCkgewogIGNvbnN0IGlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ZpbGVJbnB1dCcpOwogIGlmICghaW5wdXQuZmlsZXMubGVuZ3RoKSByZXR1cm4gc2hvd1RvYXN0KCdDaG9vc2UgYSBmaWxlIGZpcnN0JywgdHJ1ZSk7CiAgY29uc3QgZmlsZSA9IGlucHV0LmZpbGVzWzBdOwogIGlmIChmaWxlLnNpemUgPiAxMiAqIDEwMjQgKiAxMDI0KSByZXR1cm4gc2hvd1RvYXN0KCdGaWxlIHRvbyBsYXJnZSAobWF4IH4xMk1CKScsIHRydWUpOwogIHRyeSB7CiAgICBjb25zdCBiNjQgPSBhd2FpdCByZWFkRmlsZUFzQmFzZTY0KGZpbGUpOwogICAgYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvZmlsZXMnLCB7IGZpbGVuYW1lOiBmaWxlLm5hbWUsIGRlc2NyaXB0aW9uOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZmlsZURlc2MnKS52YWx1ZSwgZGF0YV9iYXNlNjQ6IGI2NCB9KTsKICAgIGNsb3NlTW9kYWwoKTsKICAgIHNob3dUb2FzdCgnRmlsZSB1cGxvYWRlZCcpOwogICAgcmVuZGVyVmlldygpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KYXN5bmMgZnVuY3Rpb24gZGVsZXRlRmlsZShpZCkgewogIGlmICghY29uZmlybSgnRGVsZXRlIHRoaXMgZmlsZT8nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL2ZpbGVzLyR7aWR9YCk7CiAgICBzaG93VG9hc3QoJ0RlbGV0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGRvd25sb2FkRmlsZShlLCBpZCwgZmlsZW5hbWUpIHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgdHJ5IHsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGAvYXBpL2ZpbGVzLyR7aWR9L2Rvd25sb2FkYCwgeyBoZWFkZXJzOiB7IEF1dGhvcml6YXRpb246ICdCZWFyZXIgJyArIHN0YXRlLnRva2VuIH0gfSk7CiAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCdEb3dubG9hZCBmYWlsZWQnKTsKICAgIGNvbnN0IGJsb2IgPSBhd2FpdCByZXMuYmxvYigpOwogICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgIGNvbnN0IGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7CiAgICBhLmhyZWYgPSB1cmw7IGEuZG93bmxvYWQgPSBmaWxlbmFtZTsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7IGEuY2xpY2soKTsgYS5yZW1vdmUoKTsKICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQogIHJldHVybiBmYWxzZTsKfQphc3luYyBmdW5jdGlvbiBwcmV2aWV3RmlsZShpZCwgZmlsZW5hbWUpIHsKICB0cnkgewogICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goYC9hcGkvZmlsZXMvJHtpZH0vZG93bmxvYWRgLCB7IGhlYWRlcnM6IHsgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgc3RhdGUudG9rZW4gfSB9KTsKICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoJ1ByZXZpZXcgZmFpbGVkJyk7CiAgICBjb25zdCBidWYgPSBhd2FpdCByZXMuYXJyYXlCdWZmZXIoKTsKICAgIGNvbnN0IHdiID0gWExTWC5yZWFkKGJ1ZiwgeyB0eXBlOiAnYXJyYXknIH0pOwogICAgY29uc3Qgc2hlZXROYW1lID0gd2IuU2hlZXROYW1lc1swXTsKICAgIGNvbnN0IHJvd3MgPSBYTFNYLnV0aWxzLnNoZWV0X3RvX2pzb24od2IuU2hlZXRzW3NoZWV0TmFtZV0sIHsgaGVhZGVyOiAxLCByYXc6IGZhbHNlIH0pOwogICAgY29uc3QgaGVhZCA9IHJvd3NbMF0gfHwgW107CiAgICBjb25zdCBib2R5ID0gcm93cy5zbGljZSgxLCAyMDEpOwogICAgY29uc3QgdGFibGVIdG1sID0gYAogICAgICA8ZGl2IGNsYXNzPSJwcmV2aWV3LXRhYmxlLXdyYXAiPgogICAgICAgIDx0YWJsZT4KICAgICAgICAgIDx0aGVhZD48dHI+JHtoZWFkLm1hcCgoaCkgPT4gYDx0aD4ke2VzYyhoKX08L3RoPmApLmpvaW4oJycpfTwvdHI+PC90aGVhZD4KICAgICAgICAgIDx0Ym9keT4ke2JvZHkubWFwKChyKSA9PiBgPHRyPiR7aGVhZC5tYXAoKF8sIGkpID0+IGA8dGQ+JHtlc2MocltpXSl9PC90ZD5gKS5qb2luKCcnKX08L3RyPmApLmpvaW4oJycpfTwvdGJvZHk+CiAgICAgICAgPC90YWJsZT4KICAgICAgPC9kaXY+CiAgICAgICR7cm93cy5sZW5ndGggPiAyMDEgPyBgPHAgY2xhc3M9InNtYWxsLW5vdGUiPlNob3dpbmcgZmlyc3QgMjAwIHJvd3Mgb2YgJHtyb3dzLmxlbmd0aCAtIDF9LjwvcD5gIDogJyd9CiAgICBgOwogICAgb3Blbk1vZGFsKGZpbGVuYW1lLCB0YWJsZUh0bWwpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoJ0NvdWxkIG5vdCBwcmV2aWV3IHRoaXMgZmlsZTogJyArIGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIFN1cnZleXMgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3U3VydmV5cyh2aWV3KSB7CiAgY29uc3QgeyBzdXJ2ZXlzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3N1cnZleXMnKTsKICBjb25zdCBjYW5NYW5hZ2UgPSBzdGF0ZS51c2VyLnJvbGUgIT09ICd2b2x1bnRlZXInOwogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10b29sYmFyIj4KICAgICAgPHAgY2xhc3M9Im11dGVkIj5MaW5rIG91dCB0byBHb29nbGUgRm9ybXMgZm9yIHN1cnZleXMsIGFuZCBHb29nbGUgU2hlZXRzIGZvciByZXN1bHRzLjwvcD4KICAgICAgJHtjYW5NYW5hZ2UgPyAnPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdTdXJ2ZXkoKSI+KyBBZGQgc3VydmV5IGxpbms8L2J1dHRvbj4nIDogJyd9CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImdyaWQiPgogICAgICAke3N1cnZleXMubGVuZ3RoID8gc3VydmV5cy5tYXAoKHMpID0+IGAKICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0LWNhcmQiPgogICAgICAgICAgPGRpdiBzdHlsZT0iZm9udC13ZWlnaHQ6NzAwOyI+JHtlc2Mocy50aXRsZSl9PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4OyBtYXJnaW4tYm90dG9tOjhweDsiPmJ5ICR7ZXNjKHMuY3JlYXRvcl9uYW1lKX0gJm1pZGRvdDsgJHtmbXREYXRlKHMuY3JlYXRlZF9hdCl9PC9kaXY+CiAgICAgICAgICAke3MuZ29vZ2xlX2Zvcm1fdXJsID8gYDxkaXY+PGEgY2xhc3M9ImxpbmsiIGhyZWY9IiR7ZXNjKHMuZ29vZ2xlX2Zvcm1fdXJsKX0iIHRhcmdldD0iX2JsYW5rIiByZWw9Im5vb3BlbmVyIj5PcGVuIGZvcm0gJnJhcnI7PC9hPjwvZGl2PmAgOiAnJ30KICAgICAgICAgICR7cy5nb29nbGVfc2hlZXRfdXJsID8gYDxkaXY+PGEgY2xhc3M9ImxpbmsiIGhyZWY9IiR7ZXNjKHMuZ29vZ2xlX3NoZWV0X3VybCl9IiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciI+VmlldyByZXN1bHRzIHNoZWV0ICZyYXJyOzwvYT48L2Rpdj5gIDogJyd9CiAgICAgICAgICAke2Nhbk1hbmFnZSA/IGA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1kYW5nZXIiIHN0eWxlPSJtYXJnaW4tdG9wOjEwcHg7IiBvbmNsaWNrPSJkZWxldGVTdXJ2ZXkoJHtzLmlkfSkiPlJlbW92ZTwvYnV0dG9uPmAgOiAnJ30KICAgICAgICA8L2Rpdj4KICAgICAgYCkuam9pbignJykgOiAnPHAgY2xhc3M9Im11dGVkIj5ObyBzdXJ2ZXlzIGFkZGVkIHlldC48L3A+J30KICAgIDwvZGl2PgogIGA7Cn0KZnVuY3Rpb24gbmV3U3VydmV5KCkgewogIG9wZW5Nb2RhbCgnQWRkIHN1cnZleSBsaW5rJywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UaXRsZTwvbGFiZWw+PGlucHV0IGlkPSJzdlRpdGxlIiBwbGFjZWhvbGRlcj0iZS5nLiBNb250aGx5IHZvbHVudGVlciBmZWVkYmFjayIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+R29vZ2xlIEZvcm0gVVJMPC9sYWJlbD48aW5wdXQgaWQ9InN2Rm9ybSIgcGxhY2Vob2xkZXI9Imh0dHBzOi8vZm9ybXMuZ29vZ2xlLmNvbS8uLi4iIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkdvb2dsZSBTaGVldCByZXN1bHRzIFVSTCAob3B0aW9uYWwpPC9sYWJlbD48aW5wdXQgaWQ9InN2U2hlZXQiIHBsYWNlaG9sZGVyPSJodHRwczovL2RvY3MuZ29vZ2xlLmNvbS9zcHJlYWRzaGVldHMvLi4uIiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdFN1cnZleSgpIj5BZGQ8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdFN1cnZleSgpIHsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvc3VydmV5cycsIHsKICAgICAgdGl0bGU6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdlRpdGxlJykudmFsdWUsCiAgICAgIGdvb2dsZV9mb3JtX3VybDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N2Rm9ybScpLnZhbHVlLAogICAgICBnb29nbGVfc2hlZXRfdXJsOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3ZTaGVldCcpLnZhbHVlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1N1cnZleSBsaW5rIGFkZGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQphc3luYyBmdW5jdGlvbiBkZWxldGVTdXJ2ZXkoaWQpIHsKICBpZiAoIWNvbmZpcm0oJ1JlbW92ZSB0aGlzIHN1cnZleSBsaW5rPycpKSByZXR1cm47CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnREVMRVRFJywgYC9hcGkvc3VydmV5cy8ke2lkfWApOwogICAgc2hvd1RvYXN0KCdSZW1vdmVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBDZXJ0aWZpY2F0ZXMgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiB2aWV3Q2VydGlmaWNhdGVzKHZpZXcpIHsKICBjb25zdCB7IGNlcnRpZmljYXRlcyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9jZXJ0aWZpY2F0ZXMnKTsKICBjb25zdCBjYW5Jc3N1ZSA9IHN0YXRlLnVzZXIucm9sZSAhPT0gJ3ZvbHVudGVlcic7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPiR7Y2FuSXNzdWUgPyAnR2VuZXJhdGUgYW5kIHRyYWNrIGNlcnRpZmljYXRlcyBpc3N1ZWQgdG8geW91ciB2b2x1bnRlZXJzLicgOiAnQ2VydGlmaWNhdGVzIGlzc3VlZCB0byB5b3UuJ308L3A+CiAgICAgICR7Y2FuSXNzdWUgPyAnPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdDZXJ0aWZpY2F0ZSgpIj4rIElzc3VlIGNlcnRpZmljYXRlPC9idXR0b24+JyA6ICcnfQogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPHRhYmxlPgogICAgICAgIDx0aGVhZD48dHI+PHRoPlZvbHVudGVlcjwvdGg+PHRoPlRpdGxlPC90aD48dGg+Tm90ZTwvdGg+PHRoPklzc3VlZCBieTwvdGg+PHRoPkRhdGU8L3RoPjx0aD48L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHk+CiAgICAgICAgICAke2NlcnRpZmljYXRlcy5sZW5ndGggPyBjZXJ0aWZpY2F0ZXMubWFwKChjKSA9PiBgCiAgICAgICAgICAgIDx0cj4KICAgICAgICAgICAgICA8dGQ+PHN0cm9uZz4ke2VzYyhjLnZvbHVudGVlcl9uYW1lKX08L3N0cm9uZz48L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhjLnRpdGxlKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyhjLm5vdGUgfHwgJycpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7ZXNjKGMuaXNzdWVyX25hbWUpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7Zm10RGF0ZShjLmNyZWF0ZWRfYXQpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSIgb25jbGljaz0iZG93bmxvYWRDZXJ0aWZpY2F0ZSgke2MuaWR9LCAnJHtlc2MoYy5jZXJ0X2NvZGUpfScpIj5Eb3dubG9hZCBQREY8L2J1dHRvbj4KICAgICAgICAgICAgICAgICR7Y2FuSXNzdWUgPyBgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tZGFuZ2VyIiBvbmNsaWNrPSJkZWxldGVDZXJ0aWZpY2F0ZSgke2MuaWR9KSI+UmV2b2tlPC9idXR0b24+YCA6ICcnfQogICAgICAgICAgICAgIDwvdGQ+CiAgICAgICAgICAgIDwvdHI+CiAgICAgICAgICBgKS5qb2luKCcnKSA6ICc8dHIgY2xhc3M9ImVtcHR5LXJvdyI+PHRkIGNvbHNwYW49IjYiPk5vIGNlcnRpZmljYXRlcyBpc3N1ZWQgeWV0LjwvdGQ+PC90cj4nfQogICAgICAgIDwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj4KICBgOwp9Cgphc3luYyBmdW5jdGlvbiBuZXdDZXJ0aWZpY2F0ZSgpIHsKICBjb25zdCB7IHVzZXJzIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL3VzZXJzJyk7CiAgY29uc3Qgdm9sdW50ZWVycyA9IHVzZXJzLmZpbHRlcigodSkgPT4gdS5yb2xlID09PSAndm9sdW50ZWVyJyAmJiB1LmFjdGl2ZSk7CiAgaWYgKCF2b2x1bnRlZXJzLmxlbmd0aCkgewogICAgb3Blbk1vZGFsKCdJc3N1ZSBjZXJ0aWZpY2F0ZScsIGA8cCBjbGFzcz0ibXV0ZWQiPk5vIHZvbHVudGVlcnMgYXZhaWxhYmxlIHlldC4gQWRkIGEgdm9sdW50ZWVyIGZpcnN0IGZyb20gdGhlIFBlb3BsZSB0YWIuPC9wPjxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+PGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNsb3NlPC9idXR0b24+PC9kaXY+YCk7CiAgICByZXR1cm47CiAgfQogIG9wZW5Nb2RhbCgnSXNzdWUgY2VydGlmaWNhdGUnLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlZvbHVudGVlcjwvbGFiZWw+CiAgICAgIDxzZWxlY3QgaWQ9ImNlcnRWb2x1bnRlZXIiPiR7dm9sdW50ZWVycy5tYXAoKHYpID0+IGA8b3B0aW9uIHZhbHVlPSIke3YuaWR9Ij4ke2VzYyh2Lm5hbWUpfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkNlcnRpZmljYXRlIHRpdGxlPC9sYWJlbD48aW5wdXQgaWQ9ImNlcnRUaXRsZSIgdmFsdWU9IkNlcnRpZmljYXRlIG9mIEFwcHJlY2lhdGlvbiIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+Tm90ZSAob3B0aW9uYWwpPC9sYWJlbD48aW5wdXQgaWQ9ImNlcnROb3RlIiBwbGFjZWhvbGRlcj0iZS5nLiBJbiByZWNvZ25pdGlvbiBvZiAxMjAgaG91cnMgb2Ygdm9sdW50ZWVyIHNlcnZpY2UgaW4gMjAyNiIgLz48L2Rpdj4KICAgIDxwIGNsYXNzPSJzbWFsbC1ub3RlIj5OYW1lcyBhcmUgcHJpbnRlZCBpbiBFbmdsaXNoL0xhdGluIHNjcmlwdCBvbiB0aGUgY2VydGlmaWNhdGUuPC9wPgogICAgPGRpdiBjbGFzcz0iZm9ybS1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCkiPkNhbmNlbDwvYnV0dG9uPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9InN1Ym1pdENlcnRpZmljYXRlKCkiPklzc3VlIGNlcnRpZmljYXRlPC9idXR0b24+CiAgICA8L2Rpdj4KICBgKTsKfQoKYXN5bmMgZnVuY3Rpb24gc3VibWl0Q2VydGlmaWNhdGUoKSB7CiAgdHJ5IHsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2NlcnRpZmljYXRlcycsIHsKICAgICAgdm9sdW50ZWVyX2lkOiBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NlcnRWb2x1bnRlZXInKS52YWx1ZSksCiAgICAgIHRpdGxlOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2VydFRpdGxlJykudmFsdWUsCiAgICAgIG5vdGU6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjZXJ0Tm90ZScpLnZhbHVlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0NlcnRpZmljYXRlIGlzc3VlZCcpOwogICAgcmVuZGVyVmlldygpOwogICAgaWYgKHJlcyAmJiByZXMuaWQpIGRvd25sb2FkQ2VydGlmaWNhdGUocmVzLmlkLCByZXMuY2VydF9jb2RlKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9Cgphc3luYyBmdW5jdGlvbiBkb3dubG9hZENlcnRpZmljYXRlKGlkLCBjZXJ0Q29kZSkgewogIHRyeSB7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChgL2FwaS9jZXJ0aWZpY2F0ZXMvJHtpZH0vZG93bmxvYWRgLCB7IGhlYWRlcnM6IHsgQXV0aG9yaXphdGlvbjogJ0JlYXJlciAnICsgc3RhdGUudG9rZW4gfSB9KTsKICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoJ0Rvd25sb2FkIGZhaWxlZCcpOwogICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgY29uc3QgYSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2EnKTsKICAgIGEuaHJlZiA9IHVybDsgYS5kb3dubG9hZCA9IGBjZXJ0aWZpY2F0ZS0ke2NlcnRDb2RlIHx8IGlkfS5wZGZgOwogICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTsgYS5jbGljaygpOyBhLnJlbW92ZSgpOwogICAgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwogIH0gY2F0Y2ggKGVycikgeyBzaG93VG9hc3QoZXJyLm1lc3NhZ2UsIHRydWUpOyB9Cn0KCmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUNlcnRpZmljYXRlKGlkKSB7CiAgaWYgKCFjb25maXJtKCdSZXZva2UgdGhpcyBjZXJ0aWZpY2F0ZT8nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL2NlcnRpZmljYXRlcy8ke2lkfWApOwogICAgc2hvd1RvYXN0KCdDZXJ0aWZpY2F0ZSByZXZva2VkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBUZWFtIC8gUGVvcGxlIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld1RlYW0odmlldykgewogIGNvbnN0IHsgdXNlcnMgfSA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvdXNlcnMnKTsKICBjb25zdCBpc1ZwID0gc3RhdGUudXNlci5yb2xlID09PSAndnAnOwogIGNvbnN0IGFkZExhYmVsID0gaXNWcCA/ICcrIEFkZCBtYW5hZ2VyJyA6ICcrIEFkZCB2b2x1bnRlZXInOwogIHZpZXcuaW5uZXJIVE1MID0gYAogICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10b29sYmFyIj4KICAgICAgPHAgY2xhc3M9Im11dGVkIj4ke2lzVnAgPyAnQWxsIG1hbmFnZXJzIGFuZCB2b2x1bnRlZXJzIGluIHRoZSBvcmdhbml6YXRpb24uJyA6ICdWb2x1bnRlZXJzIG9uIHlvdXIgdGVhbS4nfTwvcD4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJuZXdVc2VyKCkiPiR7YWRkTGFiZWx9PC9idXR0b24+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8dGFibGU+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+TmFtZTwvdGg+PHRoPkVtYWlsPC90aD48dGg+Um9sZTwvdGg+PHRoPlN0YXR1czwvdGg+PHRoPjwvdGg+PC90cj48L3RoZWFkPgogICAgICAgIDx0Ym9keT4KICAgICAgICAgICR7dXNlcnMubGVuZ3RoID8gdXNlcnMubWFwKCh1KSA9PiBgCiAgICAgICAgICAgIDx0cj4KICAgICAgICAgICAgICA8dGQ+PGEgaHJlZj0iIyIgY2xhc3M9ImxpbmsiIG9uY2xpY2s9ImV2ZW50LnByZXZlbnREZWZhdWx0KCk7IHZpZXdQcm9maWxlKCR7dS5pZH0pIj4ke2VzYyh1Lm5hbWUpfTwvYT48L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyh1LmVtYWlsKX08L3RkPgogICAgICAgICAgICAgIDx0ZD4ke2VzYyh1LnJvbGUpfTwvdGQ+CiAgICAgICAgICAgICAgPHRkPiR7dS5hY3RpdmUgPyAnPHNwYW4gY2xhc3M9ImJhZGdlIGJhZGdlLXJlc29sdmVkIj5hY3RpdmU8L3NwYW4+JyA6ICc8c3BhbiBjbGFzcz0iYmFkZ2UgYmFkZ2UtcmVqZWN0ZWQiPmluYWN0aXZlPC9zcGFuPid9PC90ZD4KICAgICAgICAgICAgICA8dGQ+JHt1LmlkICE9PSBzdGF0ZS51c2VyLmlkID8gYDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgb25jbGljaz0iZGVhY3RpdmF0ZVVzZXIoJHt1LmlkfSkiPkRlYWN0aXZhdGU8L2J1dHRvbj5gIDogJzxzcGFuIGNsYXNzPSJtdXRlZCI+eW91PC9zcGFuPid9PC90ZD4KICAgICAgICAgICAgPC90cj4KICAgICAgICAgIGApLmpvaW4oJycpIDogJzx0ciBjbGFzcz0iZW1wdHktcm93Ij48dGQgY29sc3Bhbj0iNSI+Tm8gb25lIGhlcmUgeWV0LjwvdGQ+PC90cj4nfQogICAgICAgIDwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj4KICBgOwp9Cgphc3luYyBmdW5jdGlvbiB2aWV3UHJvZmlsZShpZCkgewogIGNvbnN0IHsgdXNlcjogdSB9ID0gYXdhaXQgYXBpKCdHRVQnLCBgL2FwaS91c2Vycy8ke2lkfWApOwogIG9wZW5Nb2RhbChgUHJvZmlsZTogJHt1Lm5hbWV9YCwgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5GdWxsIG5hbWU8L2xhYmVsPjxpbnB1dCBpZD0icE5hbWUiIHZhbHVlPSIke2VzYyh1Lm5hbWUpfSIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InR3by1jb2wiPgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlBob25lPC9sYWJlbD48aW5wdXQgaWQ9InBQaG9uZSIgdmFsdWU9IiR7ZXNjKHUucGhvbmUgfHwgJycpfSIgLz48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5OYXRpb25hbCBJRDwvbGFiZWw+PGlucHV0IGlkPSJwTmF0aW9uYWxJZCIgdmFsdWU9IiR7ZXNjKHUubmF0aW9uYWxfaWQgfHwgJycpfSIgLz48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0idHdvLWNvbCI+CiAgICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RGVwYXJ0bWVudDwvbGFiZWw+PGlucHV0IGlkPSJwRGVwYXJ0bWVudCIgdmFsdWU9IiR7ZXNjKHUuZGVwYXJ0bWVudCB8fCAnJyl9IiAvPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPk1lZGljYWwgY2xlYXJhbmNlPC9sYWJlbD48aW5wdXQgaWQ9InBNZWRpY2FsIiB2YWx1ZT0iJHtlc2ModS5tZWRpY2FsX2NsZWFyYW5jZSB8fCAnJyl9IiAvPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPlNraWxsczwvbGFiZWw+PGlucHV0IGlkPSJwU2tpbGxzIiB2YWx1ZT0iJHtlc2ModS5za2lsbHMgfHwgJycpfSIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RW1lcmdlbmN5IGNvbnRhY3Q8L2xhYmVsPjxpbnB1dCBpZD0icEVtZXJnZW5jeSIgdmFsdWU9IiR7ZXNjKHUuZW1lcmdlbmN5X2NvbnRhY3QgfHwgJycpfSIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+UmVzZXQgcGFzc3dvcmQgKGxlYXZlIGJsYW5rIHRvIGtlZXAgY3VycmVudCk8L2xhYmVsPjxpbnB1dCBpZD0icFBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iTmV3IHRlbXBvcmFyeSBwYXNzd29yZCIgLz48L2Rpdj4KICAgIDxwIGlkPSJwRXJyb3IiIGNsYXNzPSJlcnJvci10ZXh0Ij48L3A+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0UHJvZmlsZSgke2lkfSkiPlNhdmU8L2J1dHRvbj4KICAgIDwvZGl2PgogIGApOwp9CmFzeW5jIGZ1bmN0aW9uIHN1Ym1pdFByb2ZpbGUoaWQpIHsKICBjb25zdCBlcnJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwRXJyb3InKTsKICBjb25zdCBwYXlsb2FkID0gewogICAgbmFtZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3BOYW1lJykudmFsdWUudHJpbSgpLAogICAgcGhvbmU6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwUGhvbmUnKS52YWx1ZSwKICAgIG5hdGlvbmFsX2lkOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncE5hdGlvbmFsSWQnKS52YWx1ZSwKICAgIGRlcGFydG1lbnQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwRGVwYXJ0bWVudCcpLnZhbHVlLAogICAgbWVkaWNhbF9jbGVhcmFuY2U6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwTWVkaWNhbCcpLnZhbHVlLAogICAgc2tpbGxzOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncFNraWxscycpLnZhbHVlLAogICAgZW1lcmdlbmN5X2NvbnRhY3Q6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwRW1lcmdlbmN5JykudmFsdWUsCiAgfTsKICBjb25zdCBuZXdQYXNzd29yZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwUGFzc3dvcmQnKS52YWx1ZTsKICBpZiAobmV3UGFzc3dvcmQpIHBheWxvYWQucGFzc3dvcmQgPSBuZXdQYXNzd29yZDsKICB0cnkgewogICAgYXdhaXQgYXBpKCdQVVQnLCBgL2FwaS91c2Vycy8ke2lkfWAsIHBheWxvYWQpOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KG5ld1Bhc3N3b3JkID8gJ1Byb2ZpbGUgc2F2ZWQgYW5kIHBhc3N3b3JkIHJlc2V0JyA6ICdQcm9maWxlIHNhdmVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IGVyckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7IH0KfQpmdW5jdGlvbiBuZXdVc2VyKCkgewogIGNvbnN0IGlzVnAgPSBzdGF0ZS51c2VyLnJvbGUgPT09ICd2cCc7CiAgb3Blbk1vZGFsKGlzVnAgPyAnQWRkIG1hbmFnZXInIDogJ0FkZCB2b2x1bnRlZXInLCBgCiAgICA8ZGl2IGNsYXNzPSJmb3JtLXJvdyI+PGxhYmVsPkZ1bGwgbmFtZTwvbGFiZWw+PGlucHV0IGlkPSJ1TmFtZSIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+RW1haWw8L2xhYmVsPjxpbnB1dCBpZD0idUVtYWlsIiB0eXBlPSJlbWFpbCIgLz48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tcm93Ij48bGFiZWw+VGVtcG9yYXJ5IHBhc3N3b3JkPC9sYWJlbD48aW5wdXQgaWQ9InVQYXNzIiB0eXBlPSJ0ZXh0IiB2YWx1ZT0iV2VsY29tZTEyMyEiIC8+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmb3JtLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIG9uY2xpY2s9ImNsb3NlTW9kYWwoKSI+Q2FuY2VsPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ic3VibWl0VXNlcignJHtpc1ZwID8gJ21hbmFnZXInIDogJ3ZvbHVudGVlcid9JykiPkFkZDwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0VXNlcihyb2xlKSB7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL3VzZXJzJywgewogICAgICBuYW1lOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndU5hbWUnKS52YWx1ZSwKICAgICAgZW1haWw6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1RW1haWwnKS52YWx1ZSwKICAgICAgcGFzc3dvcmQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1UGFzcycpLnZhbHVlLAogICAgICByb2xlLAogICAgfSk7CiAgICBjbG9zZU1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ0FkZGVkLiBTaGFyZSB0aGUgdGVtcG9yYXJ5IHBhc3N3b3JkIHdpdGggdGhlbSBzZWN1cmVseS4nKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CmFzeW5jIGZ1bmN0aW9uIGRlYWN0aXZhdGVVc2VyKGlkKSB7CiAgaWYgKCFjb25maXJtKCdEZWFjdGl2YXRlIHRoaXMgYWNjb3VudD8gVGhleSB3aWxsIG5vIGxvbmdlciBiZSBhYmxlIHRvIGxvZyBpbi4nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ0RFTEVURScsIGAvYXBpL3VzZXJzLyR7aWR9YCk7CiAgICBzaG93VG9hc3QoJ0RlYWN0aXZhdGVkJyk7CiAgICByZW5kZXJWaWV3KCk7CiAgfSBjYXRjaCAoZXJyKSB7IHNob3dUb2FzdChlcnIubWVzc2FnZSwgdHJ1ZSk7IH0KfQoKLy8gLS0tLS0tLS0tLSBBbm5vdW5jZW1lbnRzIC0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gdmlld0Fubm91bmNlbWVudHModmlldykgewogIGNvbnN0IHsgYW5ub3VuY2VtZW50cyB9ID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9hbm5vdW5jZW1lbnRzJyk7CiAgY29uc3QgY2FuUG9zdCA9IHN0YXRlLnVzZXIucm9sZSAhPT0gJ3ZvbHVudGVlcic7CiAgdmlldy5pbm5lckhUTUwgPSBgCiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uLXRvb2xiYXIiPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPlVwZGF0ZXMgZnJvbSBtYW5hZ2VycyBhbmQgdGhlIFZQLjwvcD4KICAgICAgJHtjYW5Qb3N0ID8gJzxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0ibmV3QW5ub3VuY2VtZW50KCkiPisgUG9zdCBhbm5vdW5jZW1lbnQ8L2J1dHRvbj4nIDogJyd9CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPiR7cmVuZGVyQW5ub3VuY2VtZW50TGlzdChhbm5vdW5jZW1lbnRzKX08L2Rpdj4KICBgOwp9CmZ1bmN0aW9uIG5ld0Fubm91bmNlbWVudCgpIHsKICBvcGVuTW9kYWwoJ1Bvc3QgYW5ub3VuY2VtZW50JywgYAogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5UaXRsZTwvbGFiZWw+PGlucHV0IGlkPSJhblRpdGxlIiAvPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZm9ybS1yb3ciPjxsYWJlbD5NZXNzYWdlPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImFuQm9keSI+PC90ZXh0YXJlYT48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZvcm0tYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0iY2xvc2VNb2RhbCgpIj5DYW5jZWw8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzdWJtaXRBbm5vdW5jZW1lbnQoKSI+UG9zdDwvYnV0dG9uPgogICAgPC9kaXY+CiAgYCk7Cn0KYXN5bmMgZnVuY3Rpb24gc3VibWl0QW5ub3VuY2VtZW50KCkgewogIHRyeSB7CiAgICBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9hbm5vdW5jZW1lbnRzJywgeyB0aXRsZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FuVGl0bGUnKS52YWx1ZSwgYm9keTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FuQm9keScpLnZhbHVlIH0pOwogICAgY2xvc2VNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdQb3N0ZWQnKTsKICAgIHJlbmRlclZpZXcoKTsKICB9IGNhdGNoIChlcnIpIHsgc2hvd1RvYXN0KGVyci5tZXNzYWdlLCB0cnVlKTsgfQp9CgovLyAtLS0tLS0tLS0tIEJvb3QgLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiBib290KCkgewogIGlmICghc3RhdGUudG9rZW4pIHJldHVybiBzaG93TG9naW4oKTsKICB0cnkgewogICAgY29uc3QgeyB1c2VyIH0gPSBhd2FpdCBhcGkoJ0dFVCcsICcvYXBpL21lJyk7CiAgICBzdGF0ZS51c2VyID0gdXNlcjsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2dpblNjcmVlbicpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FwcCcpLmNsYXNzTGlzdC5yZW1vdmUoJ2hpZGRlbicpOwogICAgbmF2aWdhdGUodXNlci5yb2xlID09PSAndm9sdW50ZWVyJyA/ICdhbm5vdW5jZW1lbnRzJyA6ICdkYXNoYm9hcmQnKTsKICB9IGNhdGNoIChlcnIpIHsKICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd2bXNfdG9rZW4nKTsKICAgIHNob3dMb2dpbigpOwogIH0KfQpmdW5jdGlvbiBzaG93TG9naW4oKSB7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luU2NyZWVuJykuY2xhc3NMaXN0LnJlbW92ZSgnaGlkZGVuJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FwcCcpLmNsYXNzTGlzdC5hZGQoJ2hpZGRlbicpOwp9Cgpib290KCk7Cg==', 'base64').toString('utf8');

function serveStatic(res, pathname) {
  if (pathname === '/css/style.css') {
    res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
    return res.end(STYLE_CSS);
  }
  if (pathname === '/js/app.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
    return res.end(APP_JS);
  }
  // Everything else (/, /whatever) -> single-page app shell
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(INDEX_HTML);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsed.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (!pathname.startsWith('/api/')) return serveStatic(res, pathname);

  for (const r of routes) {
    if (r.method !== req.method) continue;
    const m = pathname.match(r.regex);
    if (!m) continue;
    const params = {};
    r.keys.forEach((k, i) => (params[k] = m[i + 1]));

    const isPublic = pathname === '/api/login';
    let user = null;
    if (!isPublic) {
      user = getAuthUser(req);
      if (!user) return send(res, 401, { error: 'Unauthorized' });
    }
    try {
      await r.handler(req, res, { user, params });
    } catch (e) {
      console.error(e);
      if (!res.headersSent) send(res, 500, { error: 'Server error', detail: e.message });
    }
    return;
  }
  send(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Makkah Health Cluster Volunteer Management Portal running at http://localhost:${PORT}`);
});
