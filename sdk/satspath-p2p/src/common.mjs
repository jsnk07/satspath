import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';

export const MAX_PROFILE_BYTES = 50 * 1024;
export const GET_PROFILE = Buffer.from('GET_PROFILE\n');
export const PEER_TIMEOUT_MS = 10_000;

// Mirrors satspath-core/src/privacy.rs: trim and ASCII lowercase.
export function canonicalAlias(alias) {
  if (typeof alias !== 'string') throw new Error('Alias must be a string');
  const trimmed = alias.trim();
  if (!trimmed || /[^\x00-\x7f]/.test(trimmed)) throw new Error('Alias must be nonempty ASCII');
  return trimmed.replace(/[A-Z]/g, c => c.toLowerCase());
}

export function topicForAlias(alias) {
  return createHash('sha256').update(`satspath:v1:${canonicalAlias(alias)}`, 'utf8').digest();
}

// Structural checks only. Rust remains responsible for signature verification.
export function parseProfile(bytes, alias) {
  canonicalAlias(alias);
  if (bytes.length > MAX_PROFILE_BYTES) throw new Error('Profile exceeds 50 KB');
  const profile = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!profile || typeof profile !== 'object' || Array.isArray(profile) ||
      typeof profile.signature !== 'string' || !profile.profile ||
      typeof profile.profile !== 'object' || Array.isArray(profile.profile)) {
    throw new Error('Expected SignedPaymentProfile JSON');
  }
  if (profile.profile.alias !== alias) throw new Error('Profile alias does not exactly match requested alias');
  return profile;
}

export async function loadProfile(path, alias) {
  const file = await open(path, 'r');
  try {
    if ((await file.stat()).size > MAX_PROFILE_BYTES) throw new Error('Profile exceeds 50 KB');
    // Bounded read also protects against a file growing after stat().
    const buffer = Buffer.alloc(MAX_PROFILE_BYTES + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    const bytes = buffer.subarray(0, size);
    parseProfile(bytes, alias);
    return bytes;
  } finally {
    await file.close();
  }
}

// EOF frames the JSON response. Limits are checked before buffering each chunk.
export function readBounded(stream, maxBytes, timeoutMs = PEER_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => fail(new Error('Peer timed out')), timeoutMs);
    function cleanup() {
      clearTimeout(timer);
      stream.off('data', data);
      stream.off('end', end);
      stream.off('error', fail);
      stream.off('close', close);
    }
    function fail(error) { cleanup(); reject(error); }
    function data(chunk) {
      size += chunk.length;
      if (size > maxBytes) { fail(new Error('Response exceeds byte limit')); stream.destroy(); return; }
      chunks.push(Buffer.from(chunk));
    }
    function end() { cleanup(); resolve(Buffer.concat(chunks, size)); }
    function close() { fail(new Error('Peer closed before completing response')); }
    stream.on('data', data);
    stream.once('end', end);
    stream.once('error', fail);
    stream.once('close', close);
  });
}

export function serveProfile(stream, bytes) {
  let request = Buffer.alloc(0);
  const timer = setTimeout(() => stream.destroy(), PEER_TIMEOUT_MS);
  stream.on('error', () => console.error('Peer stream failed'));
  stream.once('close', () => clearTimeout(timer));
  stream.on('data', chunk => {
    if (request.length + chunk.length > GET_PROFILE.length) { stream.destroy(); return; }
    request = Buffer.concat([request, chunk]);
    if (!GET_PROFILE.subarray(0, request.length).equals(request)) { stream.destroy(); return; }
    if (request.length === GET_PROFILE.length) {
      stream.end(bytes);
      console.log('Public profile sent');
    }
  });
}
