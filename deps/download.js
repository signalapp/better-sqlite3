const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');

const BASE_URI = `https://build-artifacts.signal.org/desktop`;
const HASH = '9d2afebba9bfd8f18afd36a90a800df84fcf6975defacbfa1e1c5e1e8a6d05f1';
const SQLCIPHER_VERSION = '4.6.1-signal-patch2';
const EXTENSION_VERSION = '0.2.1';
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

async function download() {
  console.log(`downloading ${URL}`);
  const response = await axios({
    method: 'get',
    url: URL,
    responseType: 'stream'
  });

  console.log(`Writing to temp file ${tmpFile}`);
  const out = fs.createWriteStream(tmpFile);

  const hash = crypto.createHash('sha256');

  const t = new Transform({
    transform(chunk, encoding, callback) {
      hash.write(chunk, encoding);
      callback(null, chunk);
    }
  });

  await pipeline(response.data, t, out);

  const actualDigest = hash.digest('hex');
  if (actualDigest !== HASH) {
    fs.unlinkSync(tmpFile);
    throw new Error(`Digest mismatch. Expected ${HASH} got ${actualDigest}`);
  }

  fs.renameSync(tmpFile, finalFile);
}

main();
