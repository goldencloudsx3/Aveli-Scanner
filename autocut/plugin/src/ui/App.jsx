import React, { useState, useEffect, useRef } from 'react';
import ControlPanel from './ControlPanel';
import ProgressBar from './ProgressBar';
import CutPreview from './CutPreview';
import { getActiveSequence, getSequenceInfo, getAudioClipPaths, applyCuts } from '../api/premiere';
import { checkSidecarRunning, analyzeFile, subscribeToProgress } from '../api/sidecar';
import { getSettings, saveSettings } from '../utils/storage';

// Screens: 'main' | 'analyzing' | 'preview' | 'applying'
export default function App() {
  const [screen, setScreen] = useState('main');
  const [settings, setSettings] = useState(null);        // loaded from storage
  const [sequenceInfo, setSequenceInfo] = useState(null);
  const [sidecarRunning, setSidecarRunning] = useState(false);
  const [progress, setProgress] = useState({ stage: '', percent: 0, message: '' });
  const [cutPoints, setCutPoints] = useState([]);
  const [totalSilenceSecs, setTotalSilenceSecs] = useState(0);
  const [toast, setToast] = useState('');
  const [error, setError] = useState('');
  const cancelRef = useRef(false);
  const unsubscribeRef = useRef(null);

  // Load settings and check environment on mount
  useEffect(() => {
    (async () => {
      const saved = await getSettings();
      setSettings(saved);

      const seq = await getActiveSequence();
      if (seq) setSequenceInfo(await getSequenceInfo(seq));

      const running = await checkSidecarRunning();
      setSidecarRunning(running);
    })();
  }, []);

  // Poll for sequence changes every 3 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      const seq = await getActiveSequence();
      if (seq) {
        const info = await getSequenceInfo(seq);
        setSequenceInfo(info);
      } else {
        setSequenceInfo(null);
      }
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // Poll sidecar health every 5 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      setSidecarRunning(await checkSidecarRunning());
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  function showToast(msg) {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  }

  async function handleSettingsChange(newSettings) {
    setSettings(newSettings);
    await saveSettings(newSettings);
  }

  async function handleAnalyze() {
    cancelRef.current = false;
    setError('');
    setScreen('analyzing');
    setProgress({ stage: 'Getting clips...', percent: 0, message: '' });

    try {
      const seq = await getActiveSequence();
      if (!seq) throw new Error('No active sequence found.');

      const clips = await getAudioClipPaths(seq);
      if (clips.length === 0) throw new Error('No audio clips found in the active sequence.');

      // Subscribe to progress SSE
      unsubscribeRef.current = subscribeToProgress(({ stage, percent, message }) => {
        if (cancelRef.current) return;
        setProgress({
          stage: stage === 'extracting' ? 'Extracting audio...' : 'Detecting silences...',
          percent,
          message: message || ''
        });
      });

      // Use the first clip's media path (analyze the source file)
      // For multi-clip sequences, analyze each and merge regions
      const allCutPoints = [];
      let totalSilence = 0;

      for (let i = 0; i < clips.length; i++) {
        if (cancelRef.current) break;
        const clip = clips[i];

        setProgress({
          stage: `Analyzing clip ${i + 1} of ${clips.length}...`,
          percent: Math.round((i / clips.length) * 100),
          message: clip.mediaPath.split('/').pop()
        });

        const result = await analyzeFile(clip.mediaPath, {
          threshold: settings.threshold,
          minDuration: settings.minDuration,
          paddingBefore: settings.paddingBefore,
          paddingAfter: settings.paddingAfter
        });

        if (!result.success) throw new Error(result.error || 'Analysis failed.');

        // Offset cut points by clip start time in the sequence
        const offset = clip.startSecs;
        const offsetPoints = result.cutPoints.map(cp => ({
          start: cp.start + offset,
          end: cp.end + offset,
          durationMs: cp.durationMs
        }));

        allCutPoints.push(...offsetPoints);
        totalSilence += result.totalSilenceSecs || 0;
      }

      if (unsubscribeRef.current) unsubscribeRef.current();

      if (cancelRef.current) {
        setScreen('main');
        return;
      }

      setCutPoints(allCutPoints);
      setTotalSilenceSecs(totalSilence);
      setScreen('preview');

    } catch (err) {
      if (unsubscribeRef.current) unsubscribeRef.current();
      setError(err.message);
      setScreen('main');
    }
  }

  function handleCancel() {
    cancelRef.current = true;
    if (unsubscribeRef.current) unsubscribeRef.current();
    setScreen('main');
  }

  async function handleApplyCuts() {
    setScreen('applying');
    setProgress({ stage: 'Applying cuts to timeline...', percent: 0, message: '' });

    try {
      const seq = await getActiveSequence();
      if (!seq) throw new Error('No active sequence found.');

      const result = await applyCuts(seq, cutPoints, settings.cutMode);
      if (!result.success) throw new Error(result.error || 'Failed to apply cuts.');

      setScreen('main');
      showToast(`Done — ${cutPoints.length} regions processed`);
    } catch (err) {
      setError(err.message);
      setScreen('main');
    }
  }

  if (!settings) return <div className="panel"><div className="no-sequence">Loading...</div></div>;

  return (
    <div className="panel">
      <div className="header">
        <div>
          <div className="header-title">AutoCut</div>
          <div className="header-subtitle">Silence removal for Premiere Pro</div>
        </div>
      </div>

      {error && (
        <div className="warning-banner">
          <p style={{ color: 'var(--danger)' }}>{error}</p>
        </div>
      )}

      {screen === 'main' && (
        <ControlPanel
          settings={settings}
          onSettingsChange={handleSettingsChange}
          onAnalyze={handleAnalyze}
          sequenceInfo={sequenceInfo}
          sidecarRunning={sidecarRunning}
        />
      )}

      {(screen === 'analyzing' || screen === 'applying') && (
        <ProgressBar
          stage={progress.stage}
          percent={progress.percent}
          message={progress.message}
          onCancel={screen === 'analyzing' ? handleCancel : null}
        />
      )}

      {screen === 'preview' && (
        <CutPreview
          cutPoints={cutPoints}
          totalSilenceSecs={totalSilenceSecs}
          settings={settings}
          onApply={handleApplyCuts}
          onBack={() => setScreen('main')}
        />
      )}

      <div className={`toast ${toast ? 'visible' : ''}`}>{toast}</div>
    </div>
  );
}
