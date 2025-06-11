import getRawBody from 'raw-body';
import { webcrypto } from 'crypto';

export const config = {
  api: {
    bodyParser: false, // required for signature verification
  },
};

const { subtle } = webcrypto;
const PUBLIC_KEY_BASE64 = process.env.TELNYX_PUBLIC_KEY; // from Telnyx portal

export default async function handler(req, res) {
  try {
    const signatureHeader = req.headers['telnyx-signature-ed25519'];
    const timestamp = req.headers['telnyx-timestamp'];

    console.log('--- Webhook Debugging ---');
    console.log('Received Signature Header:', signatureHeader);
    console.log('Received Timestamp Header:', timestamp);

    if (!signatureHeader || !timestamp) {
      return res.status(400).json({ error: 'Missing Telnyx signature headers' });
    }

    const rawBody = (await getRawBody(req)).toString('utf-8');

    let canonicalBody = rawBody;
    try {
        const parsedBody = JSON.parse(rawBody);
        canonicalBody = JSON.stringify(parsedBody);
    } catch (e) {
        console.error('Failed to parse raw body as JSON, using original rawBody for verification.', e);
    }

    // --- CRITICAL CHANGE HERE: ADDING THE PIPE CHARACTER ---
    const message = new TextEncoder().encode(timestamp + '|' + canonicalBody); // <--- ADDED '|'
    // --- END CRITICAL CHANGE ---

    const signature = Buffer.from(signatureHeader, 'base64');

    console.log('Raw Body (original):\n', rawBody);
    console.log('Raw Body (canonical/minified for verification):\n', canonicalBody);
    console.log('Message to verify (timestamp + pipe + canonicalBody):\n', timestamp + '|' + canonicalBody); // Updated log message
    console.log('Signature Buffer Length:', signature.length);

    const publicKeyBuffer = Buffer.from(PUBLIC_KEY_BASE64, 'base64');
    const publicKey = await subtle.importKey(
      'raw',
      publicKeyBuffer,
      { name: 'Ed25519', namedCurve: 'Ed25519' },
      false,
      ['verify']
    );

    const isValid = await subtle.verify('Ed25519', publicKey, signature, message);

    console.log('Signature is valid:', isValid);

    if (!isValid) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const payload = JSON.parse(rawBody);
    const event = payload.data?.event_type;

    if (event === 'call.initiated') {
      return res.status(200).json({
        commands: [
          { type: 'answer' },
          {
            type: 'connect',
            to: 'sip:userhello58208@webrtc.telnyx.com'
          }
        ]
      });
    }

    return res.status(200).json({ commands: [] });

  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
