'use strict';
const Database = require('../.');

const segmenter = new Intl.Segmenter([], {
	granularity: 'word',
});

const DIACRITICS = /[\u0300-\u036f]/g;

function removeDiacritics(str) {
	return str.normalize('NFD').replace(DIACRITICS, '');
}

describe('Database#serialize()', function () {
	let aliveTokenizers;
	beforeEach(function () {
		this.db = new Database(':memory:');

		aliveTokenizers = 0;

		this.db.createTokenizer('js', class Tokenizer {
			constructor(params) {
				expect(params).to.eql(['arg1', 'arg2']);
				aliveTokenizers++;
			}

			run(str) {
				const result = [];
				let off = 0;
				for (const seg of segmenter.segment(str)) {
					const len = Buffer.byteLength(seg.segment);
					if (seg.isWordLike) {
						result.push(off, off + len, removeDiacritics(seg.segment));
					}
					off += len;
				}
				return result;
			}

			destroy() {
				aliveTokenizers--;
			}
		});

		this.db.prepare("CREATE VIRTUAL TABLE fts USING fts5(content, tokenize='js arg1 arg2')").run();
		this.insertStmt = this.db.prepare("INSERT INTO fts (content) VALUES (?)");
		this.lookupStmt = this.db.prepare(
			"SELECT snippet(fts, -1, '[', ']', '...', 10) " +
			"FROM fts " +
			"WHERE content MATCH $query").pluck();
	});
	afterEach(function () {
		this.db.close();
		expect(aliveTokenizers).to.equal(0);
	});

	it("should support CJK symbols at the start", function() {
		this.insertStmt.run("知识需要时间");
		const rows = this.lookupStmt.all({ query: "知*" });
		expect(rows).to.eql(["[知识]需要时间"]);
	});

	it("should support CJK symbols in the middle", function() {
		this.insertStmt.run("知识需要时间");
		const rows = this.lookupStmt.all({ query: "需*" });
		expect(rows).to.eql(["知识[需要]时间"]);
	});

	it("should support normalization", function() {
		this.insertStmt.run("dïācrîtįcs");
		const rows = this.lookupStmt.all({ query: "diacritics*" });
		expect(rows).to.eql(["[dïācrîtįcs]"]);
	});

	it("should support punctuation", function() {
		this.insertStmt.run("hello!world!");
		const rows = this.lookupStmt.all({ query: "h*" });
		expect(rows).to.eql(["[hello]!world!"]);
	});
});
