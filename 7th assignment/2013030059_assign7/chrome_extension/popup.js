const RULESET_ID = "taboola_images";
const FACEBOOK_SETTING = "facebookFilterEnabled";
const toggleButton = document.getElementById("toggle");
const status = document.getElementById("status");
const error = document.getElementById("error");

async function isEnabled() {
  const enabledRulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
  return enabledRulesets.includes(RULESET_ID);
}

async function refresh() {
  const enabled = await isEnabled();
  const settings = await chrome.storage.local.get(FACEBOOK_SETTING);
  if (settings[FACEBOOK_SETTING] !== enabled) {
    await chrome.storage.local.set({ [FACEBOOK_SETTING]: enabled });
  }
  status.textContent = enabled ? "ενεργοί" : "ανενεργοί";
  toggleButton.textContent = enabled ? "Απενεργοποίηση" : "Ενεργοποίηση";
  toggleButton.disabled = false;
}

toggleButton.addEventListener("click", async () => {
  toggleButton.disabled = true;
  error.hidden = true;
  try {
    const enabled = await isEnabled();
    await chrome.declarativeNetRequest.updateEnabledRulesets(
      enabled
        ? { disableRulesetIds: [RULESET_ID] }
        : { enableRulesetIds: [RULESET_ID] }
    );
    try {
      await chrome.storage.local.set({ [FACEBOOK_SETTING]: !enabled });
    } catch (cause) {
      await chrome.declarativeNetRequest.updateEnabledRulesets(
        enabled
          ? { enableRulesetIds: [RULESET_ID] }
          : { disableRulesetIds: [RULESET_ID] }
      );
      throw cause;
    }
    await refresh();
  } catch (cause) {
    error.textContent = `Δεν άλλαξαν τα φίλτρα: ${cause.message}`;
    error.hidden = false;
    toggleButton.disabled = false;
  }
});

refresh().catch((cause) => {
  status.textContent = "σφάλμα";
  error.textContent = `Δεν διαβάστηκε η κατάσταση: ${cause.message}`;
  error.hidden = false;
});
