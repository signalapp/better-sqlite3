const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');

const BASE_URI = `https://build-artifacts.signal.org/desktop`;
const HASH = '6253f886c40e49bf892d5cdc92b2eb200b12cd8d80c48ce5b05967cfd01ee8c7';
const SQLCIPHER_VERSION = '4.6.1-signal-patch2';
const EXTENSION_VERSION = '0.2.1-asm2';
const TAG = [SQLCIPHER_VERSION, EXTENSION_VERSION].join('--');
const URL = `${BASE_URI}/sqlcipher-v2-${TAG}-${HASH}.tar.gz`;

const buildFile = process.argv[2];
const targetFile = path.join(__dirname, 'sqlcipher.tar.gz');
const tmpFile = `${targetFile}.tmp`;

async function main() {
  if (fs.statSync(targetFile, { throwIfNoEntry: false })) {
    const hash = crypto.createHash('sha256');
    const existingHash = await pipeline(
      fs.createReadStream(targetFile),
      hash,
    );
    if (hash.digest('hex') === HASH) {
      console.log('local build artifact is up-to-date');
      fs.copyFileSync(targetFile, buildFile);
      return;
    }

    console.log('local build artifact is outdated');
  } else {
    console.log('local build artifact is absent');
  }
  download();
}

function download() {
  console.log(`downloading ${URL}`);
  https.get(URL, async (res) => {
    const out = fs.createWriteStream(tmpFile);

    const hash = crypto.createHash('sha256');

    const t = new Transform({
      transform(chunk, encoding, callback) {
        hash.write(chunk, encoding);
        callback(null, chunk);
      }
    });

    await pipeline(res, t, out);

    const actualDigest = hash.digest('hex');
    if (actualDigest !== HASH) {
      fs.unlinkSync(tmpFile);
      throw new Error(`Digest mismatch. Expected ${HASH} got ${actualDigest}`);
    }

    fs.renameSync(tmpFile, targetFile);
    fs.copyFileSync(targetFile, buildFile);
  });
}

main();
