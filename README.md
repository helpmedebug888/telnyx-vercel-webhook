# telnyx-vercel-webhook

Serverless webhook for [Telnyx Voice API](https://developers.telnyx.com/docs/voice) deployed on [Vercel](https://vercel.com).

## 🔧 Features

- ✅ Serverless handler written in modern ESM syntax (`.mjs`)
- ✅ Telnyx signature verification using WebCrypto API
- ✅ Secure environment variable support for Telnyx public key
- ✅ Automatically responds to `call.initiated` events

## 📁 Project Structure
api/
telnyx.mjs # Main serverless webhook handler
vercel.json # Vercel function config


## 🚀 Deployment

1. Clone the repo and push to GitHub
2. Connect to Vercel and deploy
3. Set your Telnyx public key in Vercel:
   - Add an environment variable: `TELNYX_PUBLIC_KEY`

## 🔐 Signature Verification

This webhook validates Telnyx requests using the Ed25519 signature and timestamp provided in the headers.

Ensure the following headers are present in the request:

- `telnyx-signature-ed25519`
- `telnyx-timestamp`

## 📞 Example Event Handling

Responds to `call.initiated` with:
```json
{
  "commands": [
    { "type": "answer" },
    {
      "type": "connect",
      "to": "sip:userhello58208@webrtc.telnyx.com"
    }
  ]
}
🧪 Testing Locally
Use curl to test your endpoint:
curl -X POST https://your-deployment-url.vercel.app/api/telnyx \
  -H "Content-Type: application/json" \
  -H "telnyx-signature-ed25519: your-signature" \
  -H "telnyx-timestamp: your-timestamp" \
  -d '{"data": {"event_type": "call.initiated"}}'

📄 License
## 📄 License

© 2025 Ironbridge Intelligence. All rights reserved.

This codebase is proprietary and confidential. Unauthorized copying, distribution, modification, or use of this code, via any medium, is strictly prohibited. This repository is not open source.

For internal use only. Do not fork, clone, or republish.
