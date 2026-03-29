// UXP persistent storage wrapper
// Lazily loads uxp via Function() to bypass webpack's static require transform

const SETTINGS_KEY = 'autocut_settings';

const defaults = {
  threshold: -35,
  minDuration: 0.5,
  paddingBefore: 0.1,
  paddingAfter: 0.1,
  cutMode: 'delete'
};

function getUxp() {
  try {
    return (new Function('return require("uxp")'))();
  } catch {
    return null;
  }
}

async function getSettings() {
  try {
    const uxp = getUxp();
    if (!uxp) return { ...defaults };
    const { storage } = uxp.storage;
    const folder = await storage.localFileSystem.getTemporaryFolder();
    const file = await folder.getEntry(SETTINGS_KEY + '.json').catch(() => null);
    if (!file) return { ...defaults };
    const text = await file.read({ format: storage.formats.utf8 });
    return { ...defaults, ...JSON.parse(text) };
  } catch {
    return { ...defaults };
  }
}

async function saveSettings(settings) {
  try {
    const uxp = getUxp();
    if (!uxp) return;
    const { storage } = uxp.storage;
    const folder = await storage.localFileSystem.getTemporaryFolder();
    const file = await folder.createEntry(SETTINGS_KEY + '.json', { overwrite: true });
    await file.write(JSON.stringify(settings), { format: storage.formats.utf8 });
  } catch (err) {
    console.warn('AutoCut: could not save settings', err);
  }
}

module.exports = { getSettings, saveSettings, defaults };
