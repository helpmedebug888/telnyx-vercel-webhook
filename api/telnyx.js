// trigger deploy
Trigger Vercel deploy

import getRawBody from 'raw-body';
import crypto from 'crypto';

export const config = {
  api: {
    bodyParser: false, // required for signature verification
  },
};

const PUBLIC_KEY = process.env.TELNYX_PUBLIC_KEY; // from Telnyx portal

export default async function handler(req, res) {
  try {
    const signature = req.headers['telnyx-signature-ed25519'];
    const timestamp = req.headers['telnyx-timestamp'];

    if (!signature || !timestamp) {
      return res.status(400).json({ error: 'Missing Telnyx signature headers' });
    }

    const rawBody = (await getRawBody(req)).toString('utf-8');
    const message = timestamp + rawBody;

    const isValid = crypto.verify(
      null,
      Buffer.from(message),
      {
        key: Buffer.from(PUBLIC_KEY, 'base64'),
        format: 'der',
        type: 'spki',
      },
      Buffer.from(signature, 'base64')
    );

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
            to: 'sip:userhello58208@webrtc.telnyx.com'  // ✅ your SIP username
          }
        ]
      });
    }

    // Return empty commands for unhandled events
    return res.status(200).json({ commands: [] });

  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
