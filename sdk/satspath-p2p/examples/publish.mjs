import Hyperswarm from 'hyperswarm';
import { loadProfile, topicForAlias, serveProfile } from '../src/common.mjs';

const [alias, path, ...extra] = process.argv.slice(2);
if (!alias || !path || extra.length) {
  console.error('Usage: node examples/publish.mjs <alias> <profile.json>');
  process.exitCode = 1;
} else {
  let swarm;
  let stop;
  try {
    const bytes = await loadProfile(path, alias);
    swarm = new Hyperswarm({ maxPeers: 16 });
    const stopped = new Promise(resolve => { stop = resolve; });
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    swarm.on('error', () => { console.error('Swarm failed'); process.exitCode = 1; stop(); });
    swarm.on('connection', stream => {
      console.log('Peer connected');
      stream.once('close', () => console.log('Peer disconnected'));
      serveProfile(stream, bytes);
    });
    const discovery = swarm.join(topicForAlias(alias), { server: true, client: false });
    console.log('Experimental transport: announcing public profile');
    discovery.flushed().then(() => console.log('Waiting for peers'), () => {
      console.error('Announcement failed'); process.exitCode = 1; stop();
    });
    await stopped;
  } catch {
    console.error('Publish failed: check alias, public profile JSON, size limit, and network');
    process.exitCode = 1;
  } finally {
    if (stop) { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
    if (swarm) await swarm.destroy();
  }
}
