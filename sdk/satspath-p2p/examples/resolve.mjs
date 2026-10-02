import Hyperswarm from 'hyperswarm';
import { writeFile } from 'node:fs/promises';
import { GET_PROFILE, MAX_PROFILE_BYTES, parseProfile, readBounded, topicForAlias } from '../src/common.mjs';

const [alias, output = 'profile.json', ...extra] = process.argv.slice(2);
if (!alias || extra.length) {
  console.error('Usage: node examples/resolve.mjs <alias> [output.json]');
  process.exitCode = 1;
} else {
  let swarm;
  let timer;
  let cancel;
  try {
    const topic = topicForAlias(alias);
    swarm = new Hyperswarm({ maxPeers: 16 });
    const bytes = await new Promise((resolve, reject) => {
      cancel = () => reject(new Error('Interrupted'));
      process.once('SIGINT', cancel);
      process.once('SIGTERM', cancel);
      timer = setTimeout(() => reject(new Error('Discovery timed out')), 30_000);
      swarm.on('error', () => reject(new Error('Swarm failed')));
      swarm.on('connection', async stream => {
        console.log('Peer connected');
        stream.on('error', () => {});
        try {
          const response = readBounded(stream, MAX_PROFILE_BYTES);
          stream.end(GET_PROFILE);
          const received = await response;
          parseProfile(received, alias);
          resolve(received);
        } catch {
          console.error('Peer response rejected; continuing discovery');
        } finally { stream.destroy(); }
      });
      swarm.join(topic, { server: false, client: true });
      console.log('Experimental transport: searching for public profile');
    });
    clearTimeout(timer);
    parseProfile(bytes, alias);
    // Exclusive create avoids overwriting an existing profile or following a symlink.
    // Preserve JSON number tokens and signed fields; decoding strips any UTF-8 BOM.
    await writeFile(output, new TextDecoder('utf-8', { fatal: true }).decode(bytes), { encoding: 'utf8', flag: 'wx' });
    console.log('Saved unverified public profile (UTF-8 without BOM).');
    console.log('Signature has NOT been verified. Run:');
    console.log('  satspath import --file <output.json>');
    console.log('  satspath show <alias>');
    console.log('Use the requested alias and saved output path; Rust SatsPath verifies signatures.');
  } catch {
    console.error('Resolve failed: check alias, network, and that output does not already exist');
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
    if (cancel) { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
    if (swarm) await swarm.destroy();
  }
}
