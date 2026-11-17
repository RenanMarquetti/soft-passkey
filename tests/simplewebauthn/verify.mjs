// End-to-end check against @simplewebauthn/server (requireUserVerification: true), driving the Python CLI.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const origin = 'https://login.example.com';
const rpID = 'example.com';
const root = new URL('../..', import.meta.url).pathname;
const py = process.env.PYTHON ?? join(root, '.venv/bin/python');
const dir = mkdtempSync(join(tmpdir(), 'soft-passkey-'));
const cli = (args, input) => JSON.parse(execFileSync(py, ['-m', 'soft_passkey.cli', ...args], { input, cwd: root }).toString());

const regOptions = await generateRegistrationOptions({ rpName: 'Example', rpID, userName: 'bot', userID: new TextEncoder().encode('bot-user-1'), attestationType: 'none', authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' } });
const keyFile = join(dir, 'bot.passkey');
const reg = cli(['register', '--origin', origin, '--options', '-', '--out', keyFile], JSON.stringify(regOptions));
const r = await verifyRegistrationResponse({ response: reg, expectedChallenge: regOptions.challenge, expectedOrigin: [origin], expectedRPID: rpID, requireUserVerification: true });
if (!r.verified) throw new Error('registration not verified');
const { credential } = r.registrationInfo;

const authOptions = await generateAuthenticationOptions({ rpID, allowCredentials: [{ id: credential.id }], userVerification: 'required' });
const auth = cli(['sign', '--origin', origin, '--options', '-', '--key', keyFile], JSON.stringify(authOptions));
const a = await verifyAuthenticationResponse({ response: auth, expectedChallenge: authOptions.challenge, expectedOrigin: [origin], expectedRPID: rpID, credential, requireUserVerification: true });
if (!a.verified) throw new Error('authentication not verified');

let rejected = false;
try {
  const bad = cli(['sign', '--origin', 'https://evil.example.net', '--options', '-', '--key', keyFile], JSON.stringify(authOptions));
  await verifyAuthenticationResponse({ response: bad, expectedChallenge: authOptions.challenge, expectedOrigin: [origin], expectedRPID: rpID, credential, requireUserVerification: true });
} catch { rejected = true; }
if (!rejected) throw new Error('wrong origin was accepted');
console.log('ok: @simplewebauthn/server registration + authentication with UV; wrong origin rejected');
