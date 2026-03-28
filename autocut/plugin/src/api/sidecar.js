const SIDECAR = 'http://127.0.0.1:47821';

// Check if sidecar is running — short timeout so UI doesn't hang
async function checkSidecarRunning() {
  try {
    const res = await fetch(`${SIDECAR}/health`, {
      signal: AbortSignal.timeout(2000)
    });
    return res.ok;
  } catch {
    return false;
  }
}

// Analyze a media file for silences
// Returns { success, cutPoints, count, totalSilenceSecs } or { success: false, error }
async function analyzeFile(filePath, options = {}) {
  const res = await fetch(`${SIDECAR}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filePath, ...options }),
    signal: AbortSignal.timeout(30 * 60 * 1000) // 30 min max for long files
  });
  return res.json();
}

// Subscribe to real-time progress events from the sidecar
// onProgress: ({ stage, percent, message }) => void
// Returns a cleanup function to call when done
function subscribeToProgress(onProgress) {
  const source = new EventSource(`${SIDECAR}/analyze/progress`);
  source.onmessage = (e) => {
    try { onProgress(JSON.parse(e.data)); } catch {}
  };
  return () => source.close();
}

module.exports = { checkSidecarRunning, analyzeFile, subscribeToProgress };
