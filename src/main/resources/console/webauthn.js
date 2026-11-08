// The person's own device (Windows Hello, a phone, a security key) as a passkey: the browser's WebAuthn calls and nothing
// else. This file never touches the network and never keeps anything; the server sends a fresh challenge each time and
// gets back what the device signed. The private key stays in the device.

/** Bytes to the URL-safe Base64 text that WebAuthn uses on the wire. */
function enc(buffer) {
  let s = '';
  for (const b of new Uint8Array(buffer)) s += String.fromCharCode(b);
  return btoa(s).split('+').join('-').split('/').join('_').split('=').join('');
}

function dec(text) {
  let t = String(text).split('-').join('+').split('_').join('/');
  while (t.length % 4) t += '=';
  const s = atob(t);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Can this browser use a device passkey at all? (It needs a secure page, which the console always is.) */
export function deviceSupported() {
  return typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
}

/** Asks the device to sign the server's challenge. Resolves to the JSON text the server checks. */
export async function signChallenge(opts) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: dec(opts.challenge),
      rpId: opts.rpId,
      timeout: opts.timeoutMs,
      userVerification: 'required',
      allowCredentials: opts.credentialIds.map((id) => ({type: 'public-key', id: dec(id)})),
    },
  });
  const r = cred.response;
  return JSON.stringify({id: enc(cred.rawId), clientDataJSON: enc(r.clientDataJSON), authenticatorData: enc(r.authenticatorData),
    signature: enc(r.signature)});
}

/** Asks the device to make a new passkey for this console. Resolves to the JSON text the server checks and keeps the key of. */
export async function makePasskey(opts) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: dec(opts.challenge),
      rp: {id: opts.rpId, name: 'Dwarpal'},
      user: {id: dec(opts.userId), name: opts.userName, displayName: opts.displayName},
      pubKeyCredParams: [{type: 'public-key', alg: -7}, {type: 'public-key', alg: -257}],
      authenticatorSelection: {userVerification: 'required', residentKey: 'discouraged'},
      attestation: 'none',
      timeout: opts.timeoutMs,
    },
  });
  const r = cred.response;
  return JSON.stringify({id: enc(cred.rawId), clientDataJSON: enc(r.clientDataJSON), attestationObject: enc(r.attestationObject)});
}

/** What to tell the person when the device said no (they closed the prompt, did not match, or none is set up). */
export function deviceMessage(err) {
  if (err && err.name === 'NotAllowedError') return 'Windows Hello was cancelled, timed out or did not recognise you.';
  if (err && err.name === 'InvalidStateError') return 'This device already holds a passkey for the console.';
  if (err && err.name === 'NotSupportedError') return 'This device cannot make the kind of passkey the console needs.';
  return null;
}
