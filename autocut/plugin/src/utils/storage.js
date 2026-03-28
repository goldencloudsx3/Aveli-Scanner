// UXP persistent storage wrapper
// Uses uxp.storage.localFileSystem to persist settings as a JSON file

const uxp = require('uxp');

const SETTINGS_KEY = 'autocut_settings';

const defaults = {
  threshold: -35,
  minDuration: 0.5,
  paddingBefore: 0.1,
  paddingAfter: 0.1,
  cutMode: 'delete'
};

async function getSettings() {
  try {
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
    const { storage } = uxp.storage;
    const folder = await storage.localFileSystem.getTemporaryFolder();
    const file = await folder.createEntry(SETTINGS_KEY + '.json', { overwrite: true });
    await file.write(JSON.stringify(settings), { format: storage.formats.utf8 });
  } catch (err) {
    console.warn('AutoCut: could not save settings', err);
  }
}

module.exports = { getSettings, saveSettings, defaults };
