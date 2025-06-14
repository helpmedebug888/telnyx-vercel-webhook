// api/telnyx.mjs
import getRawBody from 'raw-body';
import { webcrypto } from 'crypto';

export const config = {
  api: {
    bodyParser: false,   // must stay off for raw-body to work
  },
};

const { subtle } = webcrypto;
// raw 32-byte Ed25519 public key from your env:
const PUBLIC_KEY_RAW = Buffer.from(
  process.env.TELNYX_PUBLIC_KEY.trim(),
  'base64'
);

export default async function handler(req, res) {
  try {
    const sigHeader     = req.headers['telnyx-signature-ed25519'];
    const timestamp     = req.headers['telnyx-timestamp'];
    const contentLength = req.headers['content-length'];

    console.log('Headers:', { sigHeader, timestamp, contentLength });

    if (!sigHeader || !timestamp || !contentLength) {
      return res.status(400).json({ error: 'Missing headers' });
    }

    // 1) Read the raw buffer exactly as received
    const rawBuf  = await getRawBody(req, {
      length: contentLength,
      limit:  '1mb',
    });
    const rawBody = rawBuf.toString('utf8');

    // 2) Build the signed message = "<timestamp>|<rawBody>"
    const message   = new TextEncoder().encode(`${timestamp}|${rawBody}`);
    const signature = Buffer.from(sigHeader, 'base64');

    console.log('Raw body length:   ', rawBuf.byteLength);
    console.log('Message length:    ', message.byteLength);
    console.log('Signature length:  ', signature.length);
    console.log('Public key length: ', PUBLIC_KEY_RAW.length);

    // 3) Import your raw Ed25519 key
    const publicKey = await subtle.importKey(
      'raw',
      PUBLIC_KEY_RAW,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    // 4) Verify
    const valid = await subtle.verify(
      'Ed25519',
      publicKey,
      signature,
      message
    );
    console.log('Signature valid?', valid);

    if (!valid) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // 5) Safe to parse and respond
    const payload = JSON.parse(rawBody);
    if (payload.data?.event_type === 'call.initiated') {
      return res.status(200).json({
        commands: [
          { type: 'answer' },
          {
            type: 'connect',
            to: 'sip:agent@34.85.204.67:5060', // <--- THIS LINE HAS BEEN UPDATED
          },
        ],
      });
    }

    return res.status(200).json({ commands: [] });
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
