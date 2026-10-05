const zlib = require('zlib');

// Strict PNG / JPEG validation + sanitization for user-uploaded avatars.
//
// Checking the magic bytes alone accepts "a valid signature followed by
// anything": random junk, HTML/JS polyglots, or payloads hidden in metadata.
// Instead, the whole file is parsed against its format, anything malformed is
// rejected, and a clean copy is rebuilt from the image-data segments only.
// Metadata (EXIF incl. GPS, text chunks, comments, ICC profiles, unknown
// chunks) and any bytes after the end marker are dropped.
//
// sanitizeImage(buffer, declaredType) -> { contentType, data, width, height } | null

const MAX_DIMENSION = 8192;
// Upper bound on the decompressed PNG pixel stream we accept to inflate.
const MAX_PNG_RAW_BYTES = 64 * 1024 * 1024;

/* ------------------------------------------------------------------ */
/* PNG                                                                 */
/* ------------------------------------------------------------------ */

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// Chunks we keep in the rebuilt file (everything needed to render it right).
const PNG_KEEP = new Set(['IHDR', 'PLTE', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'IDAT', 'IEND']);
// Allowed bit depths per color type.
const PNG_DEPTHS = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
const PNG_CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
// Adam7 passes: [xStart, yStart, xStep, yStep].
const ADAM7 = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// The sub-images making up the pixel stream: one for a plain image, up to
// seven (Adam7) for an interlaced one. Each is [width, height] in pixels.
function pngPasses(width, height, interlace) {
  if (!interlace) return [[width, height]];
  return ADAM7
    .map(([xs, ys, dx, dy]) => [Math.ceil(Math.max(0, width - xs) / dx), Math.ceil(Math.max(0, height - ys) / dy)])
    .filter(([w, h]) => w > 0 && h > 0);
}

function sanitizePng(buf) {
  if (buf.length < 8 + 25 + 12 || !buf.subarray(0, 8).equals(PNG_SIGNATURE)) return null;

  const kept = [];
  const idat = [];
  let ihdr = null;
  let sawPlte = false;
  let idatState = 'none'; // none -> open -> closed (IDAT chunks must be consecutive)
  let pos = 8;

  for (;;) {
    if (pos + 12 > buf.length) return null; // truncated (no IEND)
    const len = buf.readUInt32BE(pos);
    const type = buf.toString('latin1', pos + 4, pos + 8);
    if (len > 0x7fffffff || pos + 12 + len > buf.length) return null;
    if (!/^[A-Za-z]{4}$/.test(type)) return null;
    const body = buf.subarray(pos + 4, pos + 8 + len); // type + data, as covered by the CRC
    if (crc32(body) !== buf.readUInt32BE(pos + 8 + len)) return null;
    const data = buf.subarray(pos + 8, pos + 8 + len);
    const chunk = buf.subarray(pos, pos + 12 + len);
    pos += 12 + len;

    if (!ihdr && type !== 'IHDR') return null; // IHDR must come first
    if (type === 'IHDR') {
      if (ihdr || len !== 13) return null;
      ihdr = {
        width: data.readUInt32BE(0),
        height: data.readUInt32BE(4),
        depth: data[8],
        colorType: data[9],
        compression: data[10],
        filter: data[11],
        interlace: data[12],
      };
      const { width, height, depth, colorType } = ihdr;
      if (!width || !height || width > MAX_DIMENSION || height > MAX_DIMENSION) return null;
      if (!PNG_DEPTHS[colorType] || !PNG_DEPTHS[colorType].includes(depth)) return null;
      if (ihdr.compression !== 0 || ihdr.filter !== 0 || ihdr.interlace > 1) return null;
    } else if (type === 'PLTE') {
      if (sawPlte || idatState !== 'none' || len === 0 || len % 3 !== 0 || len > 768) return null;
      sawPlte = true;
    } else if (type === 'IDAT') {
      if (idatState === 'closed') return null;
      idatState = 'open';
      idat.push(data);
    } else if (type === 'IEND') {
      if (len !== 0) return null;
      kept.push(chunk);
      break; // anything after IEND is discarded
    } else {
      // An unknown *critical* chunk (uppercase first letter) means we cannot
      // interpret the image: reject. Unknown ancillary chunks are just dropped.
      if (type[0] === type[0].toUpperCase() && !PNG_KEEP.has(type)) return null;
    }
    if (type !== 'IDAT' && idatState === 'open') idatState = 'closed';
    if (PNG_KEEP.has(type)) kept.push(chunk);
  }

  if (!idat.length) return null;
  if (ihdr.colorType === 3 && !sawPlte) return null;

  // Decompress the pixel stream and check it has exactly the size the header
  // announces, with a valid filter byte (0-4) at the start of every row. This
  // is what proves the file is an actual image and not a disguised payload.
  const bitsPerPixel = PNG_CHANNELS[ihdr.colorType] * ihdr.depth;
  const passes = pngPasses(ihdr.width, ihdr.height, ihdr.interlace);
  const rowBytes = (w) => 1 + Math.ceil((w * bitsPerPixel) / 8);
  const expected = passes.reduce((n, [w, h]) => n + h * rowBytes(w), 0);
  if (expected > MAX_PNG_RAW_BYTES) return null;

  let raw;
  try {
    raw = zlib.inflateSync(Buffer.concat(idat), { maxOutputLength: expected + 1 });
  } catch (_) {
    return null; // corrupt stream, or larger than announced
  }
  if (raw.length !== expected) return null;
  let off = 0;
  for (const [w, h] of passes) {
    const rb = rowBytes(w);
    for (let y = 0; y < h; y++, off += rb) if (raw[off] > 4) return null;
  }

  return {
    contentType: 'image/png',
    data: Buffer.concat([PNG_SIGNATURE, ...kept]),
    width: ihdr.width,
    height: ihdr.height,
  };
}

/* ------------------------------------------------------------------ */
/* JPEG                                                                */
/* ------------------------------------------------------------------ */

// SOF markers browsers decode: baseline, extended sequential, progressive.
const JPEG_SOF_OK = new Set([0xc0, 0xc1, 0xc2]);
// Other SOFs (lossless, hierarchical, arithmetic) and markers we refuse.
const JPEG_SOF_OTHER = new Set([0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

function validDqt(d) {
  let p = 0;
  while (p < d.length) {
    const pq = d[p] >> 4;
    const tq = d[p] & 0x0f;
    if (pq > 1 || tq > 3) return false;
    p += 1 + (pq ? 128 : 64);
  }
  return p === d.length && d.length > 0;
}

function validDht(d) {
  let p = 0;
  while (p < d.length) {
    if (p + 17 > d.length) return false;
    const tc = d[p] >> 4;
    const th = d[p] & 0x0f;
    if (tc > 1 || th > 3) return false;
    let n = 0;
    for (let i = 1; i <= 16; i++) n += d[p + i];
    if (n === 0 || n > 256) return false;
    p += 17 + n;
  }
  return p === d.length && d.length > 0;
}

function sanitizeJpeg(buf) {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;

  const out = [Buffer.from([0xff, 0xd8])];
  let sof = null;
  let sawDqt = false;
  let scans = 0;
  let pos = 2;

  for (;;) {
    // Expect a marker: 0xFF (possibly repeated as fill bytes) then a code.
    if (pos >= buf.length || buf[pos] !== 0xff) return null;
    while (pos < buf.length && buf[pos] === 0xff) pos++;
    if (pos >= buf.length) return null;
    const marker = buf[pos++];

    if (marker === 0xd9) break; // EOI — anything after it is discarded
    // Standalone markers (TEM, RSTn) are invalid outside entropy-coded data.
    if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) return null;

    if (pos + 2 > buf.length) return null;
    const len = buf.readUInt16BE(pos);
    if (len < 2 || pos + len > buf.length) return null;
    const seg = buf.subarray(pos - 2, pos + len); // marker + length + payload
    const d = buf.subarray(pos + 2, pos + len);
    pos += len;

    if (JPEG_SOF_OK.has(marker)) {
      if (sof) return null;
      const nf = d[5];
      if (d.length < 6 || d.length !== 6 + 3 * nf || ![1, 3, 4].includes(nf)) return null;
      const height = d.readUInt16BE(1);
      const width = d.readUInt16BE(3);
      if (d[0] !== 8 || !width || !height || width > MAX_DIMENSION || height > MAX_DIMENSION) return null;
      for (let i = 0; i < nf; i++) {
        const h = d[6 + 3 * i + 1] >> 4;
        const v = d[6 + 3 * i + 1] & 0x0f;
        if (h < 1 || h > 4 || v < 1 || v > 4 || d[6 + 3 * i + 2] > 3) return null;
      }
      sof = { width, height, nf };
      out.push(seg);
    } else if (JPEG_SOF_OTHER.has(marker) || marker === 0xcc || marker === 0xdc || marker === 0xde || marker === 0xdf) {
      return null; // unsupported coding (arithmetic, lossless, hierarchical, DNL…)
    } else if (marker === 0xdb) {
      if (!validDqt(d)) return null;
      sawDqt = true;
      out.push(seg);
    } else if (marker === 0xc4) {
      if (!validDht(d)) return null;
      out.push(seg);
    } else if (marker === 0xdd) {
      if (d.length !== 2) return null;
      out.push(seg);
    } else if (marker === 0xda) {
      if (!sof || !sawDqt) return null;
      const ns = d[0];
      if (ns < 1 || ns > 4 || d.length !== 4 + 2 * ns) return null;
      // Walk the entropy-coded data up to the next real marker. Inside it, 0xFF
      // is only legal as a stuffed 0xFF00, a restart marker, or fill.
      const start = pos;
      while (pos < buf.length) {
        if (buf[pos] !== 0xff) { pos++; continue; }
        const next = buf[pos + 1];
        if (next === 0x00 || (next >= 0xd0 && next <= 0xd7)) { pos += 2; continue; }
        if (next === 0xff) { pos++; continue; }
        break;
      }
      if (pos >= buf.length || pos === start) return null; // empty or unterminated scan
      out.push(seg, buf.subarray(start, pos));
      scans++;
    } else if (marker === 0xe0 && d.length >= 5 && d.toString('latin1', 0, 5) === 'JFIF\0') {
      out.push(seg); // JFIF header (density / version)
    } else if (marker === 0xee && d.length >= 5 && d.length <= 64 && d.toString('latin1', 0, 5) === 'Adobe') {
      out.push(seg); // Adobe color-transform flag, needed to decode some CMYK/RGB files
    } else if ((marker >= 0xe0 && marker <= 0xef) || marker === 0xfe) {
      // Other APPn (EXIF, XMP, ICC, vendor data…) and comments: dropped.
    } else {
      return null; // reserved / unknown marker
    }
  }

  if (!sof || !scans) return null;
  out.push(Buffer.from([0xff, 0xd9]));
  return { contentType: 'image/jpeg', data: Buffer.concat(out), width: sof.width, height: sof.height };
}

/* ------------------------------------------------------------------ */

// Validate `buf` as the declared image type and return a sanitized copy, or
// null when the bytes are not a well-formed image of that exact type.
function sanitizeImage(buf, declaredType) {
  if (!Buffer.isBuffer(buf)) return null;
  if (declaredType === 'image/png') return sanitizePng(buf);
  if (declaredType === 'image/jpeg') return sanitizeJpeg(buf);
  return null;
}

module.exports = { sanitizeImage };
