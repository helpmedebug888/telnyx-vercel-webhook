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

    const message = new TextEncoder().encode(timestamp + '|' + canonicalBody);
    const signature = Buffer.from(signatureHeader, 'base64');

    console.log('Raw Body (original):\n', rawBody);
    console.log('Raw Body (canonical/minified for verification):\n', canonicalBody);
    console.log('Message to verify (timestamp + pipe + canonicalBody):\n', timestamp + '|' + canonicalBody);
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

    // --- ADDED LOGS FOR PAYLOAD AND COMMANDS ---
    console.log('Parsed Payload (from rawBody):', payload);
    const event = payload.data?.event_type;
    console.log('Event Type:', event);

    if (event === 'call.initiated') {
      const commandsToSend = {
        commands: [
          { type: 'answer' },
          {
            type: 'connect',
            to: 'sip:userhello58208@webrtc.telnyx.com'
          }
        ]
      };
      console.log('Sending commands to Telnyx:', JSON.stringify(commandsToSend)); // Log the exact JSON being sent
      return res.status(200).json(commandsToSend);
    }
    // --- END ADDED LOGS ---

    console.log('No specific commands for this event type. Sending empty commands.'); // Log when no specific commands are sent
    return res.status(200).json({ commands: [] });

  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
