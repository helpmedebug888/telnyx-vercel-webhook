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

    // --- ADDED LOGS FOR DEBUGGING ---
    console.log('--- Webhook Debugging ---');
    console.log('Received Signature Header:', signatureHeader);
    console.log('Received Timestamp Header:', timestamp);
    // --- END ADDED LOGS ---

    if (!signatureHeader || !timestamp) {
      return res.status(400).json({ error: 'Missing Telnyx signature headers' });
    }

    const rawBody = (await getRawBody(req)).toString('utf-8');

    // --- NEW LINE: Trim the rawBody to remove potential whitespace issues ---
    const trimmedRawBody = rawBody.trim();
    // --- END NEW LINE ---

    const message = new TextEncoder().encode(timestamp + trimmedRawBody); // Use trimmedRawBody here!
    const signature = Buffer.from(signatureHeader, 'base64');

    // --- ADDED LOGS FOR DEBUGGING ---
    console.log('Raw Body (original):\n', rawBody); // Keep original logged for comparison
    console.log('Raw Body (trimmed):\n', trimmedRawBody); // Log trimmed version
    console.log('Message to verify (timestamp + trimmedRawBody):\n', timestamp + trimmedRawBody);
    console.log('Signature Buffer Length:', signature.length);
    // --- END ADDED LOGS ---

    const publicKeyBuffer = Buffer.from(PUBLIC_KEY_BASE64, 'base64');
    const publicKey = await subtle.importKey(
      'raw',
      publicKeyBuffer,
      { name: 'Ed25519', namedCurve: 'Ed25519' },
      false,
      ['verify']
    );

    const isValid = await subtle.verify('Ed25519', publicKey, signature, message);

    // --- ADDED LOG FOR IS_VALID ---
    console.log('Signature is valid:', isValid);
    // --- END ADDED LOG ---

    if (!isValid) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const payload = JSON.parse(rawBody); // Use original rawBody for JSON parsing
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
