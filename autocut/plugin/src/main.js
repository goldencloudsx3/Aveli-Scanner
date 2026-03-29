const React = require('react');
const ReactDOM = require('react-dom/client');
const App = require('./ui/App').default;

try {
  const rootEl = document.getElementById('root');
  if (!rootEl) {
    document.body.innerHTML =
      '<p style="color:#f44336;padding:16px;font-family:sans-serif">ERROR: root element missing</p>';
  } else {
    const root = ReactDOM.createRoot(rootEl);
    root.render(React.createElement(App));
  }
} catch (e) {
  document.body.innerHTML =
    '<p style="color:#f44336;padding:16px;font-family:sans-serif;font-size:11px">ERROR: '
    + (e && e.message ? e.message : String(e)) + '</p>';
}
