import React, { useState, useEffect } from 'react';

export default function ProgressBar({ stage, percent, message, onCancel }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2,'0')}:${String(s % 60).padStart(2,'0')}`;

  return (
    <div className="progress-wrap">
      <div className="progress-stage">{stage || 'Processing...'}</div>
      <div className="progress-bar-track">
        <div className="progress-bar-fill" style={{ width: `${percent}%` }} />
      </div>
      <div className="progress-meta">
        <span className="progress-pct">{percent}%</span>
        <span className="progress-time">{fmt(elapsed)}</span>
      </div>
      {message && <div className="progress-message">{message}</div>}
      {onCancel && <button className="btn btn-danger" onClick={onCancel}>Cancel</button>}
    </div>
  );
}
