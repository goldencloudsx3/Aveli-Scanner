// Lazily load premierepro via UXP's native require at runtime.
// Using Function() bypasses webpack's static require transformation.
function getPPro() {
  try {
    return (new Function('return require("premierepro")'))();
  } catch {
    return null;
  }
}

// Returns the active sequence object or null
async function getActiveSequence() {
  try {
    const ppro = getPPro();
    if (!ppro) return null;
    const project = await ppro.app.getProject();
    if (!project) return null;
    return project.activeSequence || null;
  } catch {
    return null;
  }
}

// Returns { name, durationSecs, fps, audioTrackCount }
async function getSequenceInfo(sequence) {
  const duration = await sequence.getEndTime();
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

function secsToTicks(secs, ticksPerSecond) {
  return BigInt(Math.round(secs * Number(ticksPerSecond)));
}

// Apply cuts to the active sequence
// mode: 'delete' (ripple delete) | 'mute' (audio keyframes)
async function applyCuts(sequence, cutPoints, mode) {
  const undoGroup = await sequence.createUndoGroup('AutoCut — Apply Cuts');
  try {
    const tps = sequence.ticksPerSecond;

    if (mode === 'delete') {
      const sorted = [...cutPoints].sort((a, b) => b.start - a.start);
      for (const { start, end } of sorted) {
        await sequence.performRippleDeleteAtRange(
          secsToTicks(start, tps),
          secsToTicks(end, tps)
        );
      }
    } else if (mode === 'mute') {
      const audioTracks = await sequence.getAudioTracks();
      for (const track of audioTracks) {
        for (const { start, end } of cutPoints) {
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
