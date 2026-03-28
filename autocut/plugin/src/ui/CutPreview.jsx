import React from 'react';

function fmtTime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = (secs % 60).toFixed(2).padStart(5, '0');
  return h > 0 ? `${h}:${String(m).padStart(2,'0')}:${s}` : `${String(m).padStart(2,'0')}:${s}`;
}

function fmtDuration(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

export default function CutPreview({ cutPoints, totalSilenceSecs, settings, onApply, onBack }) {
  const displayPoints = cutPoints.slice(0, 100);
  const modeLabel = settings.cutMode === 'delete' ? 'Delete silences' : 'Mute silences';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="preview-summary">
        <div className="preview-stat">
          <span className="preview-stat-label">Silence regions found</span>
          <span className="preview-stat-value">{cutPoints.length}</span>
        </div>
        <div className="preview-stat">
          <span className="preview-stat-label">Total silence time</span>
          <span className="preview-stat-value">{fmtDuration(totalSilenceSecs * 1000)}</span>
        </div>
        <div className="preview-stat">
          <span className="preview-stat-label">Cut mode</span>
          <span className="preview-stat-value">{modeLabel}</span>
        </div>
      </div>

      <div className="preview-list">
        <div className="preview-row preview-header">
          <span>Start</span>
          <span>End</span>
          <span>Duration</span>
        </div>
        {displayPoints.map((cp, i) => (
          <div key={i} className="preview-row">
            <span>{fmtTime(cp.start)}</span>
            <span>{fmtTime(cp.end)}</span>
            <span>{fmtDuration(cp.durationMs)}</span>
          </div>
        ))}
        {cutPoints.length > 100 && (
          <div className="preview-row" style={{ justifyContent: 'center', color: 'var(--text-muted)' }}>
            ...and {cutPoints.length - 100} more
          </div>
        )}
      </div>

      <div className="btn-row">
        <button className="btn btn-secondary" onClick={onBack}>Back</button>
        <button className="btn btn-primary" onClick={onApply}>Apply Cuts</button>
      </div>
    </div>
  );
}
