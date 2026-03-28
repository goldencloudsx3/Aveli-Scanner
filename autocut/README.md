# AutoCut

A personal-use Adobe Premiere Pro plugin that automatically detects and removes silences from video footage.

## Architecture

```
Premiere Pro
└── AutoCut UXP Panel (plugin/)
    ├── Reads sequence info via Premiere Pro API
    ├── Calls sidecar via HTTP (localhost:47821)
    └── Writes cuts back to timeline via Premiere Pro API

AutoCut Sidecar (sidecar/)
├── Receives analyze requests from plugin
├── Extracts audio via ffmpeg
├── Detects silences via ffmpeg silencedetect
└── Returns cut points as JSON
```

## Prerequisites

- **Node.js 20** or higher
- **ffmpeg** installed and on system PATH
  - macOS: `brew install ffmpeg`
  - Windows: download a static build from https://ffmpeg.org/download.html and add to PATH
- **Adobe Premiere Pro 25.6** or higher
- **Adobe UXP Developer Tool** — for installing the plugin during development

## Setup

```bash
# 1. Start the sidecar
cd autocut/sidecar
npm install
npm start
# Should print: AutoCut sidecar running on http://127.0.0.1:47821

# 2. Build the plugin
cd ../plugin
npm install
npm run build
# Outputs: plugin/dist/bundle.js

# 3. Load the plugin in Premiere Pro
# - Open Adobe UXP Developer Tool
# - Click "Add Plugin"
# - Select the plugin/manifest.json file
# - Click "Load" next to AutoCut
# - In Premiere Pro: Window → Extensions → AutoCut
```

## Development Workflow

```bash
# In one terminal — keep sidecar running:
cd sidecar && npm start

# In another terminal — auto-rebuild plugin on changes:
cd plugin && npm run watch

# Reload the plugin after changes via UXP Developer Tool "Reload" button
```

## How It Works

1. Open a sequence in Premiere Pro
2. Open the AutoCut panel (Window → Extensions → AutoCut)
3. Adjust threshold, minimum duration, and padding sliders
4. Choose cut mode (delete or mute)
5. Click **Analyze Sequence**
6. Review the list of detected silence regions
7. Click **Apply Cuts** — all cuts are made as a single undoable action (Ctrl+Z / Cmd+Z to undo)

## Settings Reference

| Setting | Default | Range | What it does |
|---|---|---|---|
| Silence threshold | -35 dB | -60 to -20 | Audio below this level is considered silence |
| Minimum duration | 0.5s | 0.1 – 3.0s | Ignore silences shorter than this |
| Keep before speech | 0.1s | 0 – 0.5s | Seconds of silence to keep before speech resumes |
| Keep after speech | 0.1s | 0 – 0.5s | Seconds of silence to keep after speech ends |

## Troubleshooting

| Problem | Fix |
|---|---|
| "Audio engine not running" warning | Start the sidecar: `cd sidecar && npm start` |
| "No audio clips found" | Make sure the active sequence has audio tracks with clips |
| Analysis returns 0 silences | Lower the threshold (e.g. -50 dB) or reduce minimum duration |
| Plugin panel won't load | Rebuild with `npm run build` and reload in UXP Developer Tool |
| Cuts applied in wrong position | Check that media file paths are accessible (no offline media) |
