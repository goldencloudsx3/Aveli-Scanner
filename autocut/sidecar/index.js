const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { extractAudio } = require('./extractor');
const { detectSilences } = require('./analyzer');

const app = express();
const PORT = 47821;
const HOST = '127.0.0.1';

// Module-level array of connected SSE clients
let progressClients = [];

// Middleware
app.use(cors({ origin: /^http:\/\/localhost(:\d+)?$/ }));
app.use(express.json());

/**
 * Emit a progress event to all connected SSE clients.
 * @param {string} stage - 'extracting' | 'analyzing'
 * @param {number} percent - 0–100
 * @param {string} [message]
 */
function emitProgress(stage, percent, message = '') {
  const payload = JSON.stringify({ stage, percent, message });
  const data = `data: ${payload}\n\n`;
  for (const res of progressClients) {
    try {
      res.write(data);
    } catch {
      // Client disconnected — will be cleaned up on close event
    }
  }
}

// GET /health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

// GET /analyze/progress — Server-Sent Events
app.get('/analyze/progress', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  progressClients.push(res);

  req.on('close', () => {
    progressClients = progressClients.filter(c => c !== res);
  });
});

// POST /analyze
app.post('/analyze', async (req, res) => {
  const {
    filePath,
    threshold = -35,
    minDuration = 0.5,
    paddingBefore = 0.1,
    paddingAfter = 0.1
  } = req.body;

  if (!filePath) {
    return res.json({ success: false, error: 'filePath is required' });
  }

  if (!fs.existsSync(filePath)) {
    return res.json({ success: false, error: `File not found: ${filePath}` });
  }

  const tempWavPath = path.join(os.tmpdir(), `autocut_${Date.now()}.wav`);

  try {
    emitProgress('extracting', 0, 'Extracting audio track...');

    await extractAudio(filePath, tempWavPath, (pct) => {
      emitProgress('extracting', pct, 'Extracting audio track...');
    });

    emitProgress('analyzing', 0, 'Detecting silences...');

    const cutPoints = await detectSilences(tempWavPath, {
      threshold,
      minDuration,
      paddingBefore,
      paddingAfter
    });

    const totalSilenceSecs = cutPoints.reduce((sum, cp) => sum + cp.durationMs / 1000, 0);

    res.json({
      success: true,
      cutPoints,
      count: cutPoints.length,
      totalSilenceSecs: Math.round(totalSilenceSecs * 10) / 10
    });
  } catch (err) {
    res.json({ success: false, error: err.message || 'Analysis failed' });
  } finally {
    try {
      fs.unlinkSync(tempWavPath);
    } catch {
      // Temp file may not exist if extraction failed early
    }
  }
});

app.listen(PORT, HOST, () => {
  console.warn(`AutoCut sidecar running on http://${HOST}:${PORT}`);
});
