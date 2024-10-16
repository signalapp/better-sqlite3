const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');

const BASE_URI = `https://build-artifacts.signal.org/desktop`;
const HASH = '4f505f35a4821c940539542f3145e5387327f83363b5f66431e265ec8103e08f';
const SQLCIPHER_VERSION = '4.6.1';
const OPENSSL_VERSION = '3.0.7';
const TOKENIZER_VERSION = '0.2.1';
const TAG = [SQLCIPHER_VERSION, OPENSSL_VERSION, TOKENIZER_VERSION].join('--');
const URL = `${BASE_URI}/sqlcipher-${TAG}-${HASH}.tar.gz`;

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
