/*
  Symmetric encryption for the local renderer <-> backend websocket.

  The shared secret is a per-launch 512-bit random token, so a slow password
  KDF is unnecessary: the AES key is derived once per token with HKDF and
  cached. Every frame still uses a fresh random nonce and is authenticated
  with AES-GCM.

  Frame format: base64(nonce[12] | ciphertext | tag[16])

  Keep this file in sync with the SCEE class in electron-preload.js.
*/

const crypto = require("crypto");

const ALGORITHM_NAME = "aes-256-gcm";
const ALGORITHM_NONCE_SIZE = 12;
const ALGORITHM_TAG_SIZE = 16;
const ALGORITHM_KEY_SIZE = 32;
const HKDF_DIGEST = "sha256";
const HKDF_SALT = "beldex-electron-wallet/ws/v2";
const HKDF_INFO = "aes-256-gcm";
const MAX_CACHED_KEYS = 4;

export class SCEE {
  constructor() {
    this.keys = new Map();
  }

  getKey(password) {
    let key = this.keys.get(password);
    if (!key) {
      key = Buffer.from(
        crypto.hkdfSync(
          HKDF_DIGEST,
          Buffer.from(password, "utf8"),
          Buffer.from(HKDF_SALT, "utf8"),
          Buffer.from(HKDF_INFO, "utf8"),
          ALGORITHM_KEY_SIZE
        )
      );
      if (this.keys.size >= MAX_CACHED_KEYS) {
        this.keys.delete(this.keys.keys().next().value);
      }
      this.keys.set(password, key);
    }
    return key;
  }

  encryptString(plaintext, password) {
    const key = this.getKey(password);
    const nonce = crypto.randomBytes(ALGORITHM_NONCE_SIZE);
    const cipher = crypto.createCipheriv(ALGORITHM_NAME, key, nonce);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final()
    ]);
    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString(
      "base64"
    );
  }

  decryptString(base64Frame, password) {
    const key = this.getKey(password);
    const frame = Buffer.from(base64Frame, "base64");
    if (frame.length < ALGORITHM_NONCE_SIZE + ALGORITHM_TAG_SIZE) {
      throw new Error("Encrypted frame too short");
    }
    const nonce = frame.subarray(0, ALGORITHM_NONCE_SIZE);
    const tag = frame.subarray(frame.length - ALGORITHM_TAG_SIZE);
    const ciphertext = frame.subarray(
      ALGORITHM_NONCE_SIZE,
      frame.length - ALGORITHM_TAG_SIZE
    );
    const decipher = crypto.createDecipheriv(ALGORITHM_NAME, key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]).toString("utf8");
  }
}
