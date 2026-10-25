import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { utils } from 'ssh2';
import { applyKeyAuth, SSHConfig } from '../src/index';

// Throwaway keys generated in-test; nothing real is read.
let dir: string;
let priv: string;
let pub: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'keyauth-'));
  const kp = utils.generateKeyPairSync('ed25519');
  priv = join(dir, 'k');
  pub = join(dir, 'k.pub');
  writeFileSync(priv, kp.private, { mode: 0o600 });
  writeFileSync(pub, kp.public);
});

const base = (): SSHConfig => ({ host: 'h', port: 22, username: 'u' });

describe('applyKeyAuth', () => {
  it('agent set: never puts a public key in privateKey', async () => {
    const c = base();
    await applyKeyAuth(c, priv, undefined, '/tmp/agent.sock');
    expect(c.agent).toBe('/tmp/agent.sock');
    expect(c.privateKey).toBeDefined();
    const parsed = utils.parseKey(c.privateKey!);
    expect(parsed instanceof Error).toBe(false);
    expect((Array.isArray(parsed) ? parsed[0] : parsed as any).isPrivateKey()).toBe(true);
  });

  it('agent set, key is only a public key: agent only, no privateKey', async () => {
    const c = base();
    await applyKeyAuth(c, pub, undefined, '/tmp/agent.sock');
    expect(c.agent).toBe('/tmp/agent.sock');
    expect(c.privateKey).toBeUndefined();
  });

  it('agent set, key missing: agent only', async () => {
    const c = base();
    await applyKeyAuth(c, join(dir, 'nope'), undefined, '/tmp/agent.sock');
    expect(c.privateKey).toBeUndefined();
    expect(c.agent).toBe('/tmp/agent.sock');
  });

  it('no agent: reads the private key file', async () => {
    const c = base();
    await applyKeyAuth(c, priv, undefined, undefined);
    expect(c.agent).toBeUndefined();
    expect(c.privateKey).toContain('PRIVATE KEY');
  });
});
