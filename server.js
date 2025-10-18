import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { createHash } from 'crypto';
import {
  importPKCS8,
  exportJWK,
  SignJWT
} from 'jose';

const app = express();

// --- Config z ENV ---
const {
  PORT = 3000,
  API_KEY,                 // np. losowy długi sekret do autoryzacji
  PRIVATE_KEY_PEM,         // klucz prywatny RSA (PKCS#8 PEM)
  KID,                     // identyfikator klucza (kid) publikowany w JWKS
  ISS,                     // domyślny issuer (opcjonalnie)
  AUD                      // domyślny audience (opcjonalnie)
} = process.env;

if (!API_KEY) console.warn('WARN: Brak API_KEY (uwierzytelnianie wyłączone).');
if (!PRIVATE_KEY_PEM) throw new Error('Brak PRIVATE_KEY_PEM w ENV.');
if (!KID) console.warn('WARN: Brak KID — JWKS będzie miał kid=null.');

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined'));

const limiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// --- Import klucza prywatnego RSA (PKCS#8) dla RS256 ---
const normalizePrivateKey = (key) =>
  key.includes('\\n') ? key.replace(/\\n/g, '\n') : key;

const privateKeyPem = normalizePrivateKey(PRIVATE_KEY_PEM);
const alg = 'RS256';
const privateKey = await importPKCS8(privateKeyPem, alg);

// Wyprowadzenie JWK publicznego i zbudowanie JWKS:
const publicJwk = await exportJWK(privateKey);
publicJwk.use = 'sig';
publicJwk.alg = alg;
publicJwk.kid = KID || null;
// Dla pewności: usuń prywatne pola (jose nie eksportuje d, ale gdybyś zmieniał kod)

// Prosty middleware API key:
function checkApiKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.header('x-api-key');
  if (key && key === API_KEY) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// Healthcheck
app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// JWKS endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [publicJwk] });
});

// Podpis JWT RS256
app.post('/sign-jwt', checkApiKey, async (req, res) => {
  try {
    const {
      payload = {},            // dowolny JSON do umieszczenia w JWT
      header = {},             // dodatkowe pola protected header, np. typ
      iss = ISS,               // issuer (opcjonalnie)
      aud = AUD,               // audience (opcjonalnie)
      sub,                     // subject (opcjonalnie)
      expiresIn = '3600s',        // np. "5m", "1h", "3600s"
      notBefore,               // np. "0s", "10s"
      jti                      // opcjonalny identyfikator tokena
    } = req.body || {};

    // Bezpieczeństwo: minimalna weryfikacja typu
    if (typeof payload !== 'object' || Array.isArray(payload)) {
      return res.status(400).json({ error: 'payload must be an object' });
    }

    // Budowa JWT:
    let jwtBuilder = new SignJWT(payload)
      .setProtectedHeader({
        alg,
        kid: KID || undefined,
        typ: header.typ || 'JWT',   // domyślnie standardowe "JWT"
        ...header                   // pozwala nadpisać/rozszerzyć
      })
      .setIssuedAt();

    if (iss) jwtBuilder = jwtBuilder.setIssuer(iss);
    if (aud) jwtBuilder = jwtBuilder.setAudience(aud);
    if (sub) jwtBuilder = jwtBuilder.setSubject(sub);
    if (jti) jwtBuilder = jwtBuilder.setJti(jti);
    if (expiresIn) jwtBuilder = jwtBuilder.setExpirationTime(expiresIn);
    if (notBefore) jwtBuilder = jwtBuilder.setNotBefore(notBefore);

    const token = await jwtBuilder.sign(privateKey);

    // Dodatkowo zwracamy thumbprint klucza (kid lub sha256 z n+e) — bywa przydatne
    const thumbprint = KID || createHash('sha256')
      .update(JSON.stringify({ e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n }))
      .digest('hex');

    res.json({
      token,
      token_type: 'JWT',
      alg,
      kid: KID || null,
      key_thumbprint: thumbprint,
      expires_in_hint: expiresIn
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'signing_failed' });
  }
});

// Start
app.listen(PORT, () => {
  console.log(`JWT signer listening on :${PORT}`);
});
