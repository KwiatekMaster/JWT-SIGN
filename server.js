import { GoogleAuth } from 'google-auth-library';
import express from 'express';

const app = express();
app.use(express.json());

// Endpoint do podpisywania JWT dla usług Google
app.post('/sign-google-jwt', async (req, res) => {
  try {
    const { target_audience } = req.body;

    if (!target_audience) {
      return res.status(400).json({ error: 'target_audience is required' });
    }

    // ✅ PRAWDŁOWE użycie zmiennych środowiskowych z Render.com
    const auth = new GoogleAuth({
      credentials: {
        client_email: process.env.GOOGLE_CLIENT_EMAIL,        // ← Zmienna środowiskowa
        private_key: process.env.GOOGLE_PRIVATE_KEY?.replace(/\\n/g, '\n')  // ← Zmienna środowiskowa
      },
      scopes: ['https://www.googleapis.com/auth/drive'],
    });

    // Generowanie tokena ID (JWT) dla określonej audiencji
    const client = await auth.getIdTokenClient(target_audience);
    
    // Pobierz token (automatycznie podpisany RS256)
    const token = await client.idTokenProvider.fetchIdToken(target_audience);

    res.json({
      success: true,
      jwt: token,
      audience: target_audience
    });

  } catch (error) {
    console.error('Error generating JWT:', error);
    res.status(500).json({ 
      error: 'Failed to generate JWT',
      details: error.message 
    });
  }
});

// Endpoint zdrowia
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'Google JWT Signer',
    client_email: process.env.GOOGLE_CLIENT_EMAIL ? 'Configured' : 'Missing' // ← Debug info
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Google JWT signing service running on port ${PORT}`);
});
