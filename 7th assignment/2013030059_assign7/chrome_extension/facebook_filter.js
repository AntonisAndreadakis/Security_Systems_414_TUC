(() => {
  const SETTING = "facebookFilterEnabled";
  const HIDDEN_CLASS = "personal-adblock-sponsored-post";
  const SPONSORED_MARKER = [
    // Greek UI.
    'a[aria-label="Διαφημιζόμενος"]',
    '[aria-label^="Άνοιγμα μενού για χορηγούμενο περιεχόμενο"]',
    // English UI. Facebook's language depends on the account/browser
    // locale, not the page's own language, so a Greek-only marker misses
    // sponsored posts for anyone not using Facebook in Greek.
    'a[aria-label="Sponsored"]'
    // The menu-button marker above has no verified English equivalent here;
    // if sponsored posts go undetected on an English-UI account, add it
    // the same way (inspect the menu button's aria-label and extend this list).
  ].join(", ");

  let enabled = false;

  function findPost(marker) {
    // Prefer a single feed post.
    const article = marker.closest('[role="article"]');
    if (article) return article;
    const feedUnit = marker.closest('[data-pagelet^="FeedUnit"]');
    if (feedUnit) return feedUnit;
    // Last resort for markup with no semantic article wrapper. This
    // attribute is also used by large, shared containers (e.g. the whole
    // feed), so only trust it when it wraps just the marker we're looking
    // at - not multiple sponsored posts at once.
    const candidate = marker.closest('div[data-visualcompletion="ignore-late-mutation"]');
    if (!candidate) return null;
    const markersInside = candidate.querySelectorAll?.(SPONSORED_MARKER) ?? [];
    return markersInside.length <= 1 ? candidate : null;
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

  // Wait for the real setting before hiding anything. `enabled` starts
  // false, so if we hid eagerly and the user had actually turned the
  // filter off, sponsored posts would flash hidden before this read
  // resolves and corrects it. hideSponsoredPosts() below does a full
  // re-scan of the document, so nothing inserted while this read is in
  // flight is missed once it resolves.
  chrome.storage.local.get({ [SETTING]: true })
    .then((settings) => setEnabled(settings[SETTING] !== false))
    .catch((error) => console.warn("Personal Adblock: Facebook filter unavailable", error));
})();
