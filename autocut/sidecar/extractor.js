const { execFile } = require('child_process');
const path = require('path');

const ffmpegBin = () => process.env.FFMPEG_PATH || 'ffmpeg';
const ffprobeBin = () => process.env.FFPROBE_PATH || 'ffprobe';

/**
 * Get total duration of a media file in seconds using ffprobe.
 * @param {string} filePath
 * @returns {Promise<number>}
 */
async function getMediaDuration(filePath) {
  return new Promise((resolve, reject) => {
    const args = [
      '-v', 'error',
      '-show_entries', 'format=duration',
      '-of', 'default=noprint_wrappers=1:nokey=1',
      filePath
    ];

    execFile(ffprobeBin(), args, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`ffprobe failed: ${stderr || err.message}`));
        return;
      }
      const duration = parseFloat(stdout.trim());
      if (isNaN(duration)) {
        reject(new Error('Could not determine media duration'));
        return;
      }
      resolve(duration);
    });
  });
}

/**
 * Extract audio from a media file to a WAV file.
 * @param {string} inputFilePath
 * @param {string} outputWavPath
 * @param {function} onProgress - called with percent (0-100) as progress changes
 * @returns {Promise<void>}
 */
async function extractAudio(inputFilePath, outputWavPath, onProgress = () => {}) {
  const totalDuration = await getMediaDuration(inputFilePath);

  return new Promise((resolve, reject) => {
    const args = [
      '-i', inputFilePath,
      '-vn',
      '-acodec', 'pcm_s16le',
      '-ar', '16000',
      '-ac', '1',
      '-y',
      outputWavPath
    ];

    const proc = execFile(ffmpegBin(), args, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`ffmpeg extraction failed: ${stderr || err.message}`));
      } else {
        resolve();
      }
    });

    let lastPercent = -1;

    proc.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      // Parse lines like "time=00:01:23.45"
      const match = text.match(/time=(\d+):(\d+):(\d+\.?\d*)/);
      if (match) {
        const h = parseInt(match[1], 10);
        const m = parseInt(match[2], 10);
        const s = parseFloat(match[3]);
        const currentSecs = h * 3600 + m * 60 + s;
        const percent = Math.min(100, Math.round((currentSecs / totalDuration) * 100));
        if (percent !== lastPercent) {
          lastPercent = percent;
          onProgress(percent);
        }
      }
    });
  });
}

module.exports = { extractAudio, getMediaDuration };
