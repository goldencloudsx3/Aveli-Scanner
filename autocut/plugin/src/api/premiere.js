const { app } = require('premierepro');

// Returns the active sequence object or null
async function getActiveSequence() {
  try {
    const project = await app.getProject();
    if (!project) return null;
    return project.activeSequence || null;
  } catch {
    return null;
  }
}

// Returns { name, durationSecs, fps, audioTrackCount }
async function getSequenceInfo(sequence) {
  const duration = await sequence.getEndTime();      // in ticks
  const tps = sequence.ticksPerSecond;
  const durationSecs = Number(duration.ticks) / Number(tps);
  const audioTracks = await sequence.getAudioTracks();
  return {
    name: sequence.name,
    durationSecs,
    fps: sequence.timebase,
    audioTrackCount: audioTracks.length
  };
}

// Returns array of { clipId, startSecs, endSecs, mediaPath }
// Collects clips from all audio tracks, deduplicates by media path
async function getAudioClipPaths(sequence) {
  const audioTracks = await sequence.getAudioTracks();
  const seen = new Set();
  const clips = [];

  for (const track of audioTracks) {
    const trackClips = await track.getClips();
    for (const clip of trackClips) {
      try {
        const item = await clip.getLinkedProjectItem();
        const mediaPath = await item.getMediaPath();
        if (mediaPath && !seen.has(mediaPath)) {
          seen.add(mediaPath);
          const startTime = await clip.getStartTime();
          const endTime = await clip.getEndTime();
          const tps = sequence.ticksPerSecond;
          clips.push({
            clipId: clip.nodeId,
            startSecs: Number(startTime.ticks) / Number(tps),
            endSecs: Number(endTime.ticks) / Number(tps),
            mediaPath
          });
        }
      } catch {
        // Skip clips with no accessible media
      }
    }
  }
  return clips;
}

// Convert seconds to Premiere ticks
function secsToTicks(secs, ticksPerSecond) {
  return BigInt(Math.round(secs * Number(ticksPerSecond)));
}

// Apply cuts to the active sequence
// cutPoints: [{ start: number, end: number }] — in seconds, relative to sequence start
// mode: 'delete' (ripple delete) | 'mute' (audio keyframes)
async function applyCuts(sequence, cutPoints, mode) {
  // Create a single undo point wrapping all edits
  const undoGroup = await sequence.createUndoGroup('AutoCut — Apply Cuts');

  try {
    const tps = sequence.ticksPerSecond;

    if (mode === 'delete') {
      // Process in reverse order so earlier edits don't shift later timecodes
      const sorted = [...cutPoints].sort((a, b) => b.start - a.start);
      for (const { start, end } of sorted) {
        const startTicks = secsToTicks(start, tps);
        const endTicks = secsToTicks(end, tps);
        await sequence.performRippleDeleteAtRange(startTicks, endTicks);
      }
    } else if (mode === 'mute') {
      const audioTracks = await sequence.getAudioTracks();
      for (const track of audioTracks) {
        for (const { start, end } of cutPoints) {
          // Set audio volume keyframes to 0 over the silence region
          await track.setVolumeKeyframe(secsToTicks(start, tps), 100);
          await track.setVolumeKeyframe(secsToTicks(start + 0.01, tps), 0);
          await track.setVolumeKeyframe(secsToTicks(end - 0.01, tps), 0);
          await track.setVolumeKeyframe(secsToTicks(end, tps), 100);
        }
      }
    }

    await undoGroup.close();
    return { success: true };
  } catch (err) {
    await undoGroup.close();
    return { success: false, error: err.message };
  }
}

module.exports = { getActiveSequence, getSequenceInfo, getAudioClipPaths, applyCuts };
