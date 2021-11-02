var globalPubkey = null;

function configKey(key) {
  globalPubkey = key;
}

function getConfigKey() {
  return globalPubkey;
}

module.exports = { configKey, getConfigKey };
