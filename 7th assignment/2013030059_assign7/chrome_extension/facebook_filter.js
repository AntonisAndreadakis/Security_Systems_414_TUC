(() => {
  const SETTING = "facebookFilterEnabled";
  const HIDDEN_CLASS = "personal-adblock-sponsored-post";
  const SPONSORED_MARKER = [
    'a[aria-label="Διαφημιζόμενος"]',
    '[aria-label^="Άνοιγμα μενού για χορηγούμενο περιεχόμενο"]'
  ].join(", ");

  let enabled = false;

  function findPost(marker) {
    // Prefer a single feed post. The last selector is a fallback for the
    // supplied Facebook markup when no semantic article wrapper exists.
    return marker.closest('[role="article"]')
      || marker.closest('[data-pagelet^="FeedUnit"]')
      || marker.closest('div[data-visualcompletion="ignore-late-mutation"]');
  }

  function hideSponsoredPosts(root) {
    if (!enabled) return;

    if (root.matches?.(SPONSORED_MARKER)) {
      const post = findPost(root);
      if (post) post.classList.add(HIDDEN_CLASS);
    }

    for (const marker of root.querySelectorAll(SPONSORED_MARKER)) {
      const post = findPost(marker);
      if (post) post.classList.add(HIDDEN_CLASS);
    }
  }

  function onMutations(records) {
    if (!enabled) return;

    for (const record of records) {
      if (record.type === "attributes") {
        hideSponsoredPosts(record.target);
      } else {
        for (const node of record.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) hideSponsoredPosts(node);
        }
      }
    }
  }

  const observer = new MutationObserver(onMutations);

  function setEnabled(nextEnabled) {
    if (enabled === nextEnabled) return;
    enabled = nextEnabled;

    if (enabled) {
      observer.observe(document.documentElement, {
        childList: true,
        attributes: true,
        attributeFilter: ["aria-label"],
        subtree: true
      });
      hideSponsoredPosts(document.documentElement);
    } else {
      observer.disconnect();
      for (const post of document.querySelectorAll(`.${HIDDEN_CLASS}`)) {
        post.classList.remove(HIDDEN_CLASS);
      }
    }
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[SETTING]) {
      setEnabled(changes[SETTING].newValue !== false);
    }
  });

  // Start before Facebook constructs its feed. Storage can turn the filter off.
  setEnabled(true);

  chrome.storage.local.get({ [SETTING]: true })
    .then((settings) => setEnabled(settings[SETTING] !== false))
    .catch((error) => console.warn("Personal Adblock: Facebook filter unavailable", error));
})();
