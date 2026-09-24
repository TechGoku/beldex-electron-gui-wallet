import Vue from "vue";

// Large lists that are only ever replaced wholesale, never edited in place.
// Freezing them stops Vue from making every entry reactive, which is the
// expensive part of committing a big transaction or master node list.
const FROZEN_LISTS = new Set([
  "tx_list",
  "nodes",
  "connections",
  "bans",
  "master_nodes_deregister",
  "signed_key_images",
  "bnsRecords"
]);

// Small flat objects that pages watch with `deep: true` and compare old vs new
// values (e.g. `status.code`). They get a fresh object on every commit so
// the watcher sees distinct old and new values.
const REPLACED_OBJECTS = new Set(["status", "secret"]);

const isPlainObject = value =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

// Merge `source` into the reactive `target` in place. Plain objects merge
// recursively (and are copied, never shared by reference); arrays and
// primitives replace the previous value. Same semantics as objectAssignDeep,
// without deep-copying the whole subtree on every commit.
export function mergeInto(target, source) {
  for (const key of Object.keys(source)) {
    let value = source[key];
    if (Array.isArray(value) && FROZEN_LISTS.has(key)) {
      value = Object.freeze(value);
    }

    if (REPLACED_OBJECTS.has(key) && isPlainObject(value)) {
      const previous = isPlainObject(target[key]) ? target[key] : {};
      const next = Object.assign({}, previous, value);
      if (key in target) target[key] = next;
      else Vue.set(target, key, next);
    } else if (isPlainObject(value)) {
      if (!isPlainObject(target[key])) {
        if (key in target) target[key] = {};
        else Vue.set(target, key, {});
      }
      mergeInto(target[key], value);
    } else if (key in target) {
      if (target[key] !== value) target[key] = value;
    } else {
      Vue.set(target, key, value);
    }
  }
}
