'use strict';
const { cppdb } = require('../util');

module.exports = function createTokenizer(name, factory) {
	// Validate arguments
	if (typeof name !== 'string') throw new TypeError('Expected first argument to be a string');
	if (!name) throw new TypeError('Virtual table module name cannot be an empty string');
	if (typeof factory !== 'function') throw new TypeError('Expected second argument to be a constructor');

	this[cppdb].createTokenizer(name, function create(params) {
		const instance = new factory(params);

		function run(str) {
			if (!instance.run) {
				// This will throw in C++
				return;
			}
			return instance.run(str);
		}

		return run;
	});
	return this;
};
