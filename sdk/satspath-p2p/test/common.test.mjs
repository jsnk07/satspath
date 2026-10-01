import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createServer, connect } from 'node:net';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalAlias, topicForAlias, parseProfile, MAX_PROFILE_BYTES, readBounded, serveProfile, loadProfile } from '../src/common.mjs';

const alias = 'alice@example.com';
const encoded = value => Buffer.from(JSON.stringify(value));
const profile = { profile: { alias }, signature: 'unverified' };

test('same alias gives same 32-byte domain-separated topic', () => {
  assert.deepEqual(topicForAlias(alias), topicForAlias(alias));
  assert.equal(topicForAlias(alias).length, 32);
  assert.equal(topicForAlias(alias).toString('hex'), '8bbd2c02caac35a3d55d4b3eb01e4a2123029e219fcf46170c89121f3595ad50');
});
test('different aliases give different topics', () => {
  assert.notDeepEqual(topicForAlias(alias), topicForAlias('bob@example.com'));
});
test('core normalization trims and lowercases ASCII', () => {
  assert.equal(canonicalAlias('  ALICE@Example.COM  '), alias);
  assert.deepEqual(topicForAlias('  ALICE@Example.COM  '), topicForAlias(alias));
  assert.throws(() => canonicalAlias('alíce@example.com'));
  assert.throws(() => canonicalAlias('  '));
});
test('alias mismatch rejected, including case differences', () => {
  assert.throws(() => parseProfile(encoded(profile), 'bob@example.com'), /alias/);
  assert.throws(() => parseProfile(encoded(profile), 'ALICE@example.com'), /alias/);
  assert.deepEqual(parseProfile(encoded(profile), alias), profile);
});
test('oversized profile rejected; exact limit accepted', () => {
  const bytes = encoded(profile);
  assert.deepEqual(parseProfile(Buffer.concat([bytes, Buffer.alloc(MAX_PROFILE_BYTES - bytes.length, 32)]), alias), profile);
  assert.throws(() => parseProfile(Buffer.alloc(MAX_PROFILE_BYTES + 1), alias), /50 KB/);
});
test('malformed JSON and invalid UTF-8 rejected', () => {
  assert.throws(() => parseProfile(Buffer.from('{'), alias));
  assert.throws(() => parseProfile(Buffer.from([0xff]), alias));
  assert.throws(() => parseProfile(encoded({ profile: { alias } }), alias));
});
test('fragmented response bounded across chunks', async () => {
  const stream = new PassThrough();
  const result = readBounded(stream, 5);
  stream.write('ab');
  stream.end('cde');
  assert.equal((await result).toString(), 'abcde');
  const oversized = new PassThrough();
  const rejected = readBounded(oversized, 5);
  oversized.write('abc');
  oversized.write('def');
  await assert.rejects(rejected, /byte limit/);
});
test('incomplete peer response times out', async () => {
  const stream = new PassThrough();
  await assert.rejects(readBounded(stream, 5, 10), /timed out/);
  stream.destroy();
});
test('publisher serves fragmented GET_PROFILE and closes response', async () => {
  const server = createServer({ allowHalfOpen: true }, stream => serveProfile(stream, encoded(profile)));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const client = connect(server.address().port, '127.0.0.1');
  try {
    await once(client, 'connect');
    const response = readBounded(client, MAX_PROFILE_BYTES);
    client.write('GET_');
    client.end('PROFILE\n');
    assert.deepEqual(parseProfile(await response, alias), profile);
  } finally {
    client.destroy();
    await new Promise(resolve => server.close(resolve));
  }
});
test('file loader rejects oversized and malformed public profiles', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'satspath-p2p-'));
  const path = join(dir, 'profile.json');
  try {
    await writeFile(path, encoded(profile));
    assert.deepEqual(await loadProfile(path, alias), encoded(profile));
    await assert.rejects(loadProfile(path, 'bob@example.com'), /alias/);
    await writeFile(path, Buffer.alloc(MAX_PROFILE_BYTES + 1));
    await assert.rejects(loadProfile(path, alias), /50 KB/);
    await writeFile(path, '{');
    await assert.rejects(loadProfile(path, alias));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
