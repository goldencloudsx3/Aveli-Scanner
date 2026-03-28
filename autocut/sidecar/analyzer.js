const { execFile } = require('child_process');

const ffmpegBin = () => process.env.FFMPEG_PATH || 'ffmpeg';

/**
 * Detect silences in an audio file using ffmpeg silencedetect filter.
 * @param {string} audioFilePath
 * @param {object} options
 * @param {number} options.threshold - dB noise floor (default: -35)
 * @param {number} options.minDuration - minimum silence length in seconds (default: 0.5)
 * @param {number} options.paddingBefore - seconds to keep before speech resumes (default: 0.1)
 * @param {number} options.paddingAfter - seconds to keep after speech ends (default: 0.1)
 * @returns {Promise<Array<{start: number, end: number, durationMs: number}>>}
 */
async function detectSilences(audioFilePath, options = {}) {
  const {
    threshold = -35,
    minDuration = 0.5,
    paddingBefore = 0.1,
    paddingAfter = 0.1
  } = options;

  return new Promise((resolve, reject) => {
    const filter = `silencedetect=noise=${threshold}dB:d=${minDuration}`;
    const args = [
      '-i', audioFilePath,
      '-af', filter,
      '-f', 'null',
      '-'
    ];

    const silences = [];
    let currentStart = null;
    let stderrBuffer = '';

    const proc = execFile(ffmpegBin(), args, (err, stdout, stderr) => {
      if (err && err.code !== 1) {
        // ffmpeg exits with code 1 when output is /dev/null — that's normal
        // Only reject on genuine errors (non-zero exit that isn't 1 with stderr indicating failure)
        const isExpectedExit = stderr && stderr.includes('silencedetect');
        if (!isExpectedExit) {
          reject(new Error(`ffmpeg silencedetect failed: ${stderr || err.message}`));
          return;
        }
      }

      // Process any remaining buffered stderr
      processLines(stderrBuffer);
      resolve(silences);
    });

    function processLines(text) {
      const lines = text.split('\n');
      for (const line of lines) {
        const startMatch = line.match(/silence_start:\s*([\d.]+)/);
        const endMatch = line.match(/silence_end:\s*([\d.]+)/);

        if (startMatch) {
          currentStart = parseFloat(startMatch[1]);
        }

        if (endMatch && currentStart !== null) {
          const silenceEnd = parseFloat(endMatch[1]);
          const silenceStart = currentStart;

          const start = Math.max(0, silenceStart - paddingAfter);
          const end = silenceEnd + paddingBefore;
          const durationMs = Math.round((silenceEnd - silenceStart) * 1000);

          silences.push({ start, end, durationMs });
          currentStart = null;
        }
      }
    }

    proc.stderr.on('data', (chunk) => {
      stderrBuffer += chunk.toString();
      // Process complete lines only, keep partial last line in buffer
      const lastNewline = stderrBuffer.lastIndexOf('\n');
      if (lastNewline !== -1) {
        processLines(stderrBuffer.substring(0, lastNewline));
        stderrBuffer = stderrBuffer.substring(lastNewline + 1);
      }
    });
  });
}

module.exports = { detectSilences };
