import getRawBody from 'raw-body';
import { webcrypto } from 'crypto';

export const config = {
  api: {
    bodyParser: false,   // must stay off
  },
};

const { subtle } = webcrypto;
// raw Ed25519 public key from your env:
const PUBLIC_KEY_RAW = Buffer.from(
  process.env.TELNYX_PUBLIC_KEY.trim(),
  'base64'
);

export default async function handler(req, res) {
  try {
    const sigHeader = req.headers['telnyx-signature-ed25519'];
    const timestamp = req.headers['telnyx-timestamp'];
    const contentLength = req.headers['content-length'];

    console.log('Headers:', {
      sigHeader,
      timestamp,
      contentLength,
    });

    if (!sigHeader || !timestamp || !contentLength) {
      return res.status(400).json({ error: 'Missing headers' });
    }

    // read EXACT raw body
    const rawBuf = await getRawBody(req, {
      length: contentLength,
      limit: '1mb',
    });
    const rawBody = rawBuf.toString('utf8');

    // canonicalize (minify) JSON
    let canonical = rawBody;
    try {
      canonical = JSON.stringify(JSON.parse(rawBody));
    } catch {
      // if parsing fails, stick with rawBody
    }

    // build message = `${timestamp}|${canonical}`
    const message = new TextEncoder().encode(`${timestamp}|${canonical}`);
    const signature = Buffer.from(sigHeader, 'base64');

    console.log('Raw body length:', rawBuf.byteLength);
    console.log('Canonical length:', Buffer.byteLength(canonical, 'utf8'));
    console.log('Message length:', message.byteLength);
    console.log('Signature length:', signature.length);
    console.log('Public key length:', PUBLIC_KEY_RAW.length);

    // import as raw Ed25519
    const publicKey = await subtle.importKey(
      'raw',
      PUBLIC_KEY_RAW,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

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

    // at this point you can safely parse and respond
    const payload = JSON.parse(rawBody);
    if (payload.data?.event_type === 'call.initiated') {
      return res.status(200).json({
        commands: [
          { type: 'answer' },
          {
            type: 'connect',
            to: 'sip:userhello58208@webrtc.telnyx.com',
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
