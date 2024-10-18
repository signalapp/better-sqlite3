const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');

const BASE_URI = `https://build-artifacts.signal.org/desktop`;
const HASH = '4f9381902020998f2d2c2015bdf341484736cd9af7330af194e604a2851e1450';
const SQLCIPHER_VERSION = '4.6.1';
const EXTENSION_VERSION = '0.1.0';
const TAG = [SQLCIPHER_VERSION, EXTENSION_VERSION].join('--');
const URL = `${BASE_URI}/sqlcipher-v2-${TAG}-${HASH}.tar.gz`;

const tmpFile = path.join(__dirname, 'unverified.tmp');
const finalFile = path.join(__dirname, 'sqlcipher.tar.gz');

async function main() {
  if (fs.statSync(finalFile, { throwIfNoEntry: false })) {
    const hash = crypto.createHash('sha256');
    const existingHash = await pipeline(
      fs.createReadStream(finalFile),
      hash,
    );
    if (hash.digest('hex') === HASH) {
      console.log('local build artifact is up-to-date');
      return;
    }

    console.log('local build artifact is outdated');
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

    fs.renameSync(tmpFile, finalFile);
  })
}

main();
