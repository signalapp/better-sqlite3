'use strict';
const path = require('path');
const tar = require('tar');

const source = process.argv[2];
const dest = process.argv[3];

process.on('unhandledRejection', (err) => { throw err; });

/*
	This extracts the bundled sqlcipher.tar.gz file and places the resulting files
	into the directory specified by <$2>.
 */

tar.extract({ file: source, cwd: dest, onwarn: process.emitWarning })
	.then(() => process.exit(0));
