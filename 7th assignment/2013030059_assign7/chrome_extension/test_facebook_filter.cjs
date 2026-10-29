const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "facebook_filter.js"), "utf8");
const hiddenClass = "personal-adblock-sponsored-post";

function makePost(nestedMarkerCount = 0) {
  const classes = new Set();
  return {
    classList: {
      add: (value) => classes.add(value),
      remove: (value) => classes.delete(value),
      contains: (value) => classes.has(value)
    },
    // Used only by the fallback `data-visualcompletion` branch, to tell a
    // single post's own wrapper apart from a large, shared container that
    // happens to carry the same attribute.
    querySelectorAll: () => new Array(nestedMarkerCount).fill(null)
  };
}

function makeHarness() {
  const markers = [];
  const posts = [];
  let storageListener;
  let observer;

  class FakeObserver {
    constructor(callback) {
      this.callback = callback;
      this.active = false;
      observer = this;
    }
    observe() { this.active = true; }
    disconnect() { this.active = false; }
  }

  const sandbox = {
    Node: { ELEMENT_NODE: 1 },
    MutationObserver: FakeObserver,
    document: {
      documentElement: {
        matches: () => false,
        querySelectorAll: () => markers
      },
      querySelectorAll(selector) {
        return selector === `.${hiddenClass}`
          ? posts.filter((post) => post.classList.contains(hiddenClass))
          : markers;
      }
    },
    chrome: {
      storage: {
        local: { get: async () => ({ facebookFilterEnabled: true }) },
        onChanged: { addListener: (listener) => { storageListener = listener; } }
      }
    },
    console
  };

  vm.runInNewContext(source, sandbox, { filename: "facebook_filter.js" });

  return {
    addMarker(post, fallback = false) {
      posts.push(post);
      const marker = {
        nodeType: 1,
        matches: () => true,
        querySelectorAll: () => [],
        closest(selector) {
          if (!fallback && selector === '[role="article"]') return post;
          if (fallback && selector === 'div[data-visualcompletion="ignore-late-mutation"]') return post;
          return null;
        }
      };
      markers.push(marker);
      return marker;
    },
    changeEnabled(value) {
      storageListener({ facebookFilterEnabled: { newValue: value } }, "local");
    },
    notifyMutation(node) {
      if (observer.active) {
        observer.callback([{ type: "childList", addedNodes: [node] }]);
      }
    },
    isObserving: () => observer.active
  };
}

test("hides only marked posts, including posts added later, and restores them", async () => {
  const harness = makeHarness();
  const sponsored = makePost();
  const normal = makePost();
  const firstMarker = harness.addMarker(sponsored);
  harness.notifyMutation(firstMarker);

  await new Promise(setImmediate);
  assert.equal(sponsored.classList.contains(hiddenClass), true);
  assert.equal(normal.classList.contains(hiddenClass), false);

  const laterSponsored = makePost();
  const laterMarker = harness.addMarker(laterSponsored, true);
  harness.notifyMutation(laterMarker);
  assert.equal(laterSponsored.classList.contains(hiddenClass), true);

  harness.changeEnabled(false);
  assert.equal(harness.isObserving(), false);
  assert.equal(sponsored.classList.contains(hiddenClass), false);
  assert.equal(laterSponsored.classList.contains(hiddenClass), false);

  harness.changeEnabled(true);
  assert.equal(harness.isObserving(), true);
  assert.equal(sponsored.classList.contains(hiddenClass), true);
  assert.equal(laterSponsored.classList.contains(hiddenClass), true);
});

test("the data-visualcompletion fallback refuses a container shared by more than one post", async () => {
  const harness = makeHarness();
  // Two sponsored markers inside the same candidate container (post has
  // nestedMarkerCount=2): this looks like a shared wrapper (e.g. the whole
  // feed), not one post's own wrapper, so it must not be hidden.
  const sharedContainer = makePost(2);
  const marker = harness.addMarker(sharedContainer, true);
  harness.notifyMutation(marker);

  await new Promise(setImmediate);
  assert.equal(sharedContainer.classList.contains(hiddenClass), false);
});
