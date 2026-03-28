import React from 'react';

export default function ControlPanel({ settings, onSettingsChange, onAnalyze, sequenceInfo, sidecarRunning }) {

  function update(key, value) {
    onSettingsChange({ ...settings, [key]: value });
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>

      {/* Sequence info */}
      {sequenceInfo ? (
        <div className="sequence-banner">
          <div className="sequence-name">{sequenceInfo.name}</div>
          <div className="sequence-meta">
            {formatDuration(sequenceInfo.durationSecs)} &nbsp;·&nbsp; {sequenceInfo.audioTrackCount} audio track{sequenceInfo.audioTrackCount !== 1 ? 's' : ''}
          </div>
        </div>
      ) : (
        <div className="no-sequence">Open a sequence in Premiere Pro to begin</div>
      )}

      {/* Sidecar warning */}
      {!sidecarRunning && (
        <div className="warning-banner">
          <p>Audio engine not running. In a terminal, run:<br />
          <code>cd autocut/sidecar && npm start</code></p>
        </div>
      )}

      <hr className="divider" />

      {/* Threshold */}
      <div>
        <div className="section-label">Detection settings</div>
        <div className="slider-row">
          <div className="slider-header">
            <span className="slider-label">Silence threshold</span>
            <span className="slider-value">{settings.threshold} dB</span>
          </div>
          <input type="range" min="-60" max="-20" step="1"
            value={settings.threshold}
            onChange={e => update('threshold', Number(e.target.value))} />
        </div>

        <div className="slider-row">
          <div className="slider-header">
            <span className="slider-label">Minimum silence length</span>
            <span className="slider-value">{settings.minDuration}s</span>
          </div>
          <input type="range" min="0.1" max="3.0" step="0.1"
            value={settings.minDuration}
            onChange={e => update('minDuration', Number(e.target.value))} />
        </div>
      </div>

      {/* Padding */}
      <div>
        <div className="section-label">Padding</div>
        <div className="slider-row">
          <div className="slider-header">
            <span className="slider-label">Keep before speech</span>
            <span className="slider-value">{settings.paddingBefore}s</span>
          </div>
          <input type="range" min="0" max="0.5" step="0.05"
            value={settings.paddingBefore}
            onChange={e => update('paddingBefore', Number(e.target.value))} />
        </div>

        <div className="slider-row">
          <div className="slider-header">
            <span className="slider-label">Keep after speech</span>
            <span className="slider-value">{settings.paddingAfter}s</span>
          </div>
          <input type="range" min="0" max="0.5" step="0.05"
            value={settings.paddingAfter}
            onChange={e => update('paddingAfter', Number(e.target.value))} />
        </div>
      </div>

      {/* Cut mode */}
      <div>
        <div className="section-label">Cut mode</div>
        <div className="radio-group">
          <label className="radio-option">
            <input type="radio" name="cutMode" value="delete"
              checked={settings.cutMode === 'delete'}
              onChange={() => update('cutMode', 'delete')} />
            <div className="radio-label">
              Delete silences
              <span>Ripple-delete silence regions from timeline</span>
            </div>
          </label>
          <label className="radio-option">
            <input type="radio" name="cutMode" value="mute"
              checked={settings.cutMode === 'mute'}
              onChange={() => update('cutMode', 'mute')} />
            <div className="radio-label">
              Mute silences
              <span>Keep clips in place, mute audio in silence regions</span>
            </div>
          </label>
        </div>
      </div>

      <hr className="divider" />

      <button
        className="btn btn-primary"
        disabled={!sequenceInfo || !sidecarRunning}
        onClick={onAnalyze}
      >
        Analyze Sequence
      </button>
    </div>
  );
}

function formatDuration(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
