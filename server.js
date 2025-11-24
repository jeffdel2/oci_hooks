require('dotenv').config();
const express = require('express');
const tokenHook = require('./tokenHook');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Okta inline token hook endpoint
app.post('/token-hook', (req, res) => {
  try {
    const result = tokenHook.processTokenHook(req.body);
    res.status(200).json(result);
  } catch (error) {
    console.error('Error processing token hook:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

