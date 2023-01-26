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
	beforeEach(function () {
		this.db = new Database(':memory:');

		this.db.prepare("CREATE VIRTUAL TABLE fts USING fts5(content, tokenize='icu_tokenizer')").run();
		this.insertStmt = this.db.prepare("INSERT INTO fts (content) VALUES (?)");
		this.lookupStmt = this.db.prepare(
			"SELECT snippet(fts, -1, '[', ']', '...', 20) " +
			"FROM fts " +
			"WHERE content MATCH $query").pluck();
	});
	afterEach(function () {
		this.db.close();
	});

	it("should support CJK symbols at the start", function() {
		this.insertStmt.run("知识需要时间");
		const rows = this.lookupStmt.all({ query: "知*" });
		expect(rows).to.eql(["[知]识需要时间"]);
	});

	it("should support CJK symbols in the middle", function() {
		this.insertStmt.run("知识需要时间");
		const rows = this.lookupStmt.all({ query: "需*" });
		expect(rows).to.eql(["知识[需]要时间"]);
	});

	it("should support Korean symbols", function() {
		this.insertStmt.run("안녕 세상");
		const rows = this.lookupStmt.all({ query: "세*" });
		expect(rows).to.eql(["안녕 [세상]"]);
	});

	it("should support normalization", function() {
		this.insertStmt.run("dïācrîtįcs");
		const rows = this.lookupStmt.all({ query: "diacritics*" });
		expect(rows).to.eql(["[dïācrîtįcs]"]);
	});

	it("should support punctuation", function() {
		this.insertStmt.run("Hello!world!  how are you?");
		const rows = this.lookupStmt.all({ query: "h*" });
		expect(rows).to.eql(["[Hello]!world!  [how] are you?"]);
	});
});
