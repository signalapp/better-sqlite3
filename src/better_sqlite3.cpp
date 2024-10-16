// better_sqlite3.cpp
//

#include "better_sqlite3.hpp"
static bool IsPlainObject(v8::Isolate* isolate, v8::Local<v8::Object> obj) {
  v8::Local<v8::Value> proto = obj->GetPrototype();

#if defined NODE_MODULE_VERSION && NODE_MODULE_VERSION < 93
  v8::Local<v8::Context> ctx = obj->CreationContext();
#else
  v8::Local<v8::Context> ctx = obj->GetCreationContext().ToLocalChecked();
#endif

  ctx->Enter();
  v8::Local<v8::Value> baseProto = v8::Object::New(isolate)->GetPrototype();
  ctx->Exit();
  return proto->StrictEquals(baseProto) ||
         proto->StrictEquals(v8::Null(isolate));
}
NODE_MODULE_INIT(/* exports, context */) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Initialize addon instance.
  Addon* addon = new Addon(isolate);
  v8::Local<v8::External> data = v8::External::New(isolate, addon);
  node::AddEnvironmentCleanupHook(isolate, Addon::Cleanup, addon);

  // Create and export native-backed classes and functions.
  exports
      ->Set(context, InternalizedFromLatin1(isolate, "Database"),
            Database::Init(isolate, data))
      .FromJust();
  exports
      ->Set(context, InternalizedFromLatin1(isolate, "Statement"),
            Statement::Init(isolate, data))
      .FromJust();
  exports
      ->Set(context, InternalizedFromLatin1(isolate, "StatementIterator"),
            StatementIterator::Init(isolate, data))
      .FromJust();
  exports
      ->Set(context, InternalizedFromLatin1(isolate, "Backup"),
            Backup::Init(isolate, data))
      .FromJust();
  exports
      ->Set(context, InternalizedFromLatin1(isolate, "setErrorConstructor"),
            v8::FunctionTemplate::New(isolate, Addon::JS_setErrorConstructor,
                                      data)
                ->GetFunction(context)
                .ToLocalChecked())
      .FromJust();
  exports
      ->Set(context, InternalizedFromLatin1(isolate, "setLogHandler"),
            v8::FunctionTemplate::New(isolate, Addon::JS_setLogHandler, data)
                ->GetFunction(context)
                .ToLocalChecked())
      .FromJust();

  // Store addon instance data.
  addon->Statement.Reset(
      isolate,
      exports->Get(context, InternalizedFromLatin1(isolate, "Statement"))
          .ToLocalChecked()
          .As<v8::Function>());
  addon->StatementIterator.Reset(
      isolate,
      exports
          ->Get(context, InternalizedFromLatin1(isolate, "StatementIterator"))
          .ToLocalChecked()
          .As<v8::Function>());
  addon->Backup.Reset(
      isolate, exports->Get(context, InternalizedFromLatin1(isolate, "Backup"))
                   .ToLocalChecked()
                   .As<v8::Function>());
}
#define LZZ_INLINE inline
namespace Data {
static char const FLAT = 0;
static char const PLUCK = 1;
static char const EXPAND = 2;
static char const RAW = 3;
}  // namespace Data
void ThrowError(char const* message) {
  v8 ::Isolate* isolate = v8 ::Isolate ::GetCurrent();
  isolate->ThrowException(
      v8::Exception::Error(StringFromUtf8(isolate, message, -1)));
}
void ThrowTypeError(char const* message) {
  v8 ::Isolate* isolate = v8 ::Isolate ::GetCurrent();
  isolate->ThrowException(
      v8::Exception::TypeError(StringFromUtf8(isolate, message, -1)));
}
void ThrowRangeError(char const* message) {
  v8 ::Isolate* isolate = v8 ::Isolate ::GetCurrent();
  isolate->ThrowException(
      v8::Exception::RangeError(StringFromUtf8(isolate, message, -1)));
}
v8::Local<v8::FunctionTemplate> NewConstructorTemplate(
    v8::Isolate* isolate,
    v8::Local<v8::External> data,
    v8::FunctionCallback func,
    char const* name) {
  v8::Local<v8::FunctionTemplate> t =
      v8::FunctionTemplate::New(isolate, func, data);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(InternalizedFromLatin1(isolate, name));
  return t;
}
void SetPrototypeMethod(v8::Isolate* isolate,
                        v8::Local<v8::External> data,
                        v8::Local<v8::FunctionTemplate> recv,
                        char const* name,
                        v8::FunctionCallback func) {
  v8::HandleScope scope(isolate);
  recv->PrototypeTemplate()->Set(
      InternalizedFromLatin1(isolate, name),
      v8::FunctionTemplate::New(isolate, func, data,
                                v8::Signature::New(isolate, recv)));
}
void SetPrototypeSymbolMethod(v8::Isolate* isolate,
                              v8::Local<v8::External> data,
                              v8::Local<v8::FunctionTemplate> recv,
                              v8::Local<v8::Symbol> symbol,
                              v8::FunctionCallback func) {
  v8::HandleScope scope(isolate);
  recv->PrototypeTemplate()->Set(
      symbol, v8::FunctionTemplate::New(isolate, func, data,
                                        v8::Signature::New(isolate, recv)));
}
void SetPrototypeGetter(v8::Isolate* isolate,
                        v8::Local<v8::External> data,
                        v8::Local<v8::FunctionTemplate> recv,
                        char const* name,
                        v8::FunctionCallback func) {
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> func_tpl =
      v8::FunctionTemplate::New(isolate, func, data);
  recv->InstanceTemplate()->SetAccessorProperty(
      InternalizedFromLatin1(isolate, name), func_tpl);
}
v8::Local<v8::String> CS::Code(v8::Isolate* isolate, int code) {
  auto element = codes.find(code);
  if (element != codes.end())
    return element->second.Get(isolate);
  return StringFromUtf8(
      isolate,
      (std::string("UNKNOWN_SQLITE_ERROR_") + std::to_string(code)).c_str(),
      -1);
}
CS::CS(v8::Isolate* isolate) {
  SetString(isolate, database, "database");
  SetString(isolate, reader, "reader");
  SetString(isolate, source, "source");
  SetString(isolate, memory, "memory");
  SetString(isolate, readonly, "readonly");
  SetString(isolate, name, "name");
  SetString(isolate, next, "next");
  SetString(isolate, length, "length");
  SetString(isolate, done, "done");
  SetString(isolate, value, "value");
  SetString(isolate, changes, "changes");
  SetString(isolate, lastInsertRowid, "lastInsertRowid");
  SetString(isolate, statement, "statement");
  SetString(isolate, column, "column");
  SetString(isolate, table, "table");
  SetString(isolate, type, "type");
  SetString(isolate, totalPages, "totalPages");
  SetString(isolate, remainingPages, "remainingPages");

  SetCode(isolate, SQLITE_OK, "SQLITE_OK");
  SetCode(isolate, SQLITE_ERROR, "SQLITE_ERROR");
  SetCode(isolate, SQLITE_INTERNAL, "SQLITE_INTERNAL");
  SetCode(isolate, SQLITE_PERM, "SQLITE_PERM");
  SetCode(isolate, SQLITE_ABORT, "SQLITE_ABORT");
  SetCode(isolate, SQLITE_BUSY, "SQLITE_BUSY");
  SetCode(isolate, SQLITE_LOCKED, "SQLITE_LOCKED");
  SetCode(isolate, SQLITE_NOMEM, "SQLITE_NOMEM");
  SetCode(isolate, SQLITE_READONLY, "SQLITE_READONLY");
  SetCode(isolate, SQLITE_INTERRUPT, "SQLITE_INTERRUPT");
  SetCode(isolate, SQLITE_IOERR, "SQLITE_IOERR");
  SetCode(isolate, SQLITE_CORRUPT, "SQLITE_CORRUPT");
  SetCode(isolate, SQLITE_NOTFOUND, "SQLITE_NOTFOUND");
  SetCode(isolate, SQLITE_FULL, "SQLITE_FULL");
  SetCode(isolate, SQLITE_CANTOPEN, "SQLITE_CANTOPEN");
  SetCode(isolate, SQLITE_PROTOCOL, "SQLITE_PROTOCOL");
  SetCode(isolate, SQLITE_EMPTY, "SQLITE_EMPTY");
  SetCode(isolate, SQLITE_SCHEMA, "SQLITE_SCHEMA");
  SetCode(isolate, SQLITE_TOOBIG, "SQLITE_TOOBIG");
  SetCode(isolate, SQLITE_CONSTRAINT, "SQLITE_CONSTRAINT");
  SetCode(isolate, SQLITE_MISMATCH, "SQLITE_MISMATCH");
  SetCode(isolate, SQLITE_MISUSE, "SQLITE_MISUSE");
  SetCode(isolate, SQLITE_NOLFS, "SQLITE_NOLFS");
  SetCode(isolate, SQLITE_AUTH, "SQLITE_AUTH");
  SetCode(isolate, SQLITE_FORMAT, "SQLITE_FORMAT");
  SetCode(isolate, SQLITE_RANGE, "SQLITE_RANGE");
  SetCode(isolate, SQLITE_NOTADB, "SQLITE_NOTADB");
  SetCode(isolate, SQLITE_NOTICE, "SQLITE_NOTICE");
  SetCode(isolate, SQLITE_WARNING, "SQLITE_WARNING");
  SetCode(isolate, SQLITE_ROW, "SQLITE_ROW");
  SetCode(isolate, SQLITE_DONE, "SQLITE_DONE");
  SetCode(isolate, SQLITE_IOERR_READ, "SQLITE_IOERR_READ");
  SetCode(isolate, SQLITE_IOERR_SHORT_READ, "SQLITE_IOERR_SHORT_READ");
  SetCode(isolate, SQLITE_IOERR_WRITE, "SQLITE_IOERR_WRITE");
  SetCode(isolate, SQLITE_IOERR_FSYNC, "SQLITE_IOERR_FSYNC");
  SetCode(isolate, SQLITE_IOERR_DIR_FSYNC, "SQLITE_IOERR_DIR_FSYNC");
  SetCode(isolate, SQLITE_IOERR_TRUNCATE, "SQLITE_IOERR_TRUNCATE");
  SetCode(isolate, SQLITE_IOERR_FSTAT, "SQLITE_IOERR_FSTAT");
  SetCode(isolate, SQLITE_IOERR_UNLOCK, "SQLITE_IOERR_UNLOCK");
  SetCode(isolate, SQLITE_IOERR_RDLOCK, "SQLITE_IOERR_RDLOCK");
  SetCode(isolate, SQLITE_IOERR_DELETE, "SQLITE_IOERR_DELETE");
  SetCode(isolate, SQLITE_IOERR_BLOCKED, "SQLITE_IOERR_BLOCKED");
  SetCode(isolate, SQLITE_IOERR_NOMEM, "SQLITE_IOERR_NOMEM");
  SetCode(isolate, SQLITE_IOERR_ACCESS, "SQLITE_IOERR_ACCESS");
  SetCode(isolate, SQLITE_IOERR_CHECKRESERVEDLOCK,
          "SQLITE_IOERR_CHECKRESERVEDLOCK");
  SetCode(isolate, SQLITE_IOERR_LOCK, "SQLITE_IOERR_LOCK");
  SetCode(isolate, SQLITE_IOERR_CLOSE, "SQLITE_IOERR_CLOSE");
  SetCode(isolate, SQLITE_IOERR_DIR_CLOSE, "SQLITE_IOERR_DIR_CLOSE");
  SetCode(isolate, SQLITE_IOERR_SHMOPEN, "SQLITE_IOERR_SHMOPEN");
  SetCode(isolate, SQLITE_IOERR_SHMSIZE, "SQLITE_IOERR_SHMSIZE");
  SetCode(isolate, SQLITE_IOERR_SHMLOCK, "SQLITE_IOERR_SHMLOCK");
  SetCode(isolate, SQLITE_IOERR_SHMMAP, "SQLITE_IOERR_SHMMAP");
  SetCode(isolate, SQLITE_IOERR_SEEK, "SQLITE_IOERR_SEEK");
  SetCode(isolate, SQLITE_IOERR_DELETE_NOENT, "SQLITE_IOERR_DELETE_NOENT");
  SetCode(isolate, SQLITE_IOERR_MMAP, "SQLITE_IOERR_MMAP");
  SetCode(isolate, SQLITE_IOERR_GETTEMPPATH, "SQLITE_IOERR_GETTEMPPATH");
  SetCode(isolate, SQLITE_IOERR_CONVPATH, "SQLITE_IOERR_CONVPATH");
  SetCode(isolate, SQLITE_IOERR_VNODE, "SQLITE_IOERR_VNODE");
  SetCode(isolate, SQLITE_IOERR_AUTH, "SQLITE_IOERR_AUTH");
  SetCode(isolate, SQLITE_LOCKED_SHAREDCACHE, "SQLITE_LOCKED_SHAREDCACHE");
  SetCode(isolate, SQLITE_BUSY_RECOVERY, "SQLITE_BUSY_RECOVERY");
  SetCode(isolate, SQLITE_BUSY_SNAPSHOT, "SQLITE_BUSY_SNAPSHOT");
  SetCode(isolate, SQLITE_CANTOPEN_NOTEMPDIR, "SQLITE_CANTOPEN_NOTEMPDIR");
  SetCode(isolate, SQLITE_CANTOPEN_ISDIR, "SQLITE_CANTOPEN_ISDIR");
  SetCode(isolate, SQLITE_CANTOPEN_FULLPATH, "SQLITE_CANTOPEN_FULLPATH");
  SetCode(isolate, SQLITE_CANTOPEN_CONVPATH, "SQLITE_CANTOPEN_CONVPATH");
  SetCode(isolate, SQLITE_CORRUPT_VTAB, "SQLITE_CORRUPT_VTAB");
  SetCode(isolate, SQLITE_READONLY_RECOVERY, "SQLITE_READONLY_RECOVERY");
  SetCode(isolate, SQLITE_READONLY_CANTLOCK, "SQLITE_READONLY_CANTLOCK");
  SetCode(isolate, SQLITE_READONLY_ROLLBACK, "SQLITE_READONLY_ROLLBACK");
  SetCode(isolate, SQLITE_READONLY_DBMOVED, "SQLITE_READONLY_DBMOVED");
  SetCode(isolate, SQLITE_ABORT_ROLLBACK, "SQLITE_ABORT_ROLLBACK");
  SetCode(isolate, SQLITE_CONSTRAINT_CHECK, "SQLITE_CONSTRAINT_CHECK");
  SetCode(isolate, SQLITE_CONSTRAINT_COMMITHOOK,
          "SQLITE_CONSTRAINT_COMMITHOOK");
  SetCode(isolate, SQLITE_CONSTRAINT_FOREIGNKEY,
          "SQLITE_CONSTRAINT_FOREIGNKEY");
  SetCode(isolate, SQLITE_CONSTRAINT_FUNCTION, "SQLITE_CONSTRAINT_FUNCTION");
  SetCode(isolate, SQLITE_CONSTRAINT_NOTNULL, "SQLITE_CONSTRAINT_NOTNULL");
  SetCode(isolate, SQLITE_CONSTRAINT_PRIMARYKEY,
          "SQLITE_CONSTRAINT_PRIMARYKEY");
  SetCode(isolate, SQLITE_CONSTRAINT_TRIGGER, "SQLITE_CONSTRAINT_TRIGGER");
  SetCode(isolate, SQLITE_CONSTRAINT_UNIQUE, "SQLITE_CONSTRAINT_UNIQUE");
  SetCode(isolate, SQLITE_CONSTRAINT_VTAB, "SQLITE_CONSTRAINT_VTAB");
  SetCode(isolate, SQLITE_CONSTRAINT_ROWID, "SQLITE_CONSTRAINT_ROWID");
  SetCode(isolate, SQLITE_NOTICE_RECOVER_WAL, "SQLITE_NOTICE_RECOVER_WAL");
  SetCode(isolate, SQLITE_NOTICE_RECOVER_ROLLBACK,
          "SQLITE_NOTICE_RECOVER_ROLLBACK");
  SetCode(isolate, SQLITE_WARNING_AUTOINDEX, "SQLITE_WARNING_AUTOINDEX");
  SetCode(isolate, SQLITE_AUTH_USER, "SQLITE_AUTH_USER");
  SetCode(isolate, SQLITE_OK_LOAD_PERMANENTLY, "SQLITE_OK_LOAD_PERMANENTLY");
}
void CS::SetString(v8::Isolate* isolate,
                   CopyablePersistent<v8::String>& constant,
                   char const* str) {
  constant.Reset(isolate, InternalizedFromLatin1(isolate, str));
}
void CS::SetCode(v8::Isolate* isolate, int code, char const* str) {
  codes.emplace(
      std::piecewise_construct, std::forward_as_tuple(code),
      std::forward_as_tuple(isolate, InternalizedFromLatin1(isolate, str)));
}
BindMap::Pair::Pair(v8::Isolate* isolate, char const* name, int index)
    : name(isolate, InternalizedFromUtf8(isolate, name, -1)), index(index) {}
BindMap::Pair::Pair(v8::Isolate* isolate, Pair* pair)
    : name(isolate, pair->name), index(pair->index) {}
BindMap::BindMap(char _) {
  assert(_ == 0);
  pairs = NULL;
  capacity = 0;
  length = 0;
}
BindMap::~BindMap() {
  while (length)
    pairs[--length].~Pair();
  FREE_ARRAY<Pair>(pairs);
}
void BindMap::Add(v8::Isolate* isolate, char const* name, int index) {
  assert(name != NULL);
  if (capacity == length)
    Grow(isolate);
  new (pairs + length++) Pair(isolate, name, index);
}
void BindMap::Grow(v8::Isolate* isolate) {
  assert(capacity == length);
  capacity = (capacity << 1) | 2;
  Pair* new_pairs = ALLOC_ARRAY<Pair>(capacity);
  for (int i = 0; i < length; ++i) {
    new (new_pairs + i) Pair(isolate, pairs + i);
    pairs[i].~Pair();
  }
  FREE_ARRAY<Pair>(pairs);
  pairs = new_pairs;
}
v8::Local<v8 ::Function> Database::Init(v8::Isolate* isolate,
                                        v8::Local<v8 ::External> data) {
  v8::Local<v8::FunctionTemplate> t =
      NewConstructorTemplate(isolate, data, JS_new, "Database");
  SetPrototypeMethod(isolate, data, t, "prepare", JS_prepare);
  SetPrototypeMethod(isolate, data, t, "exec", JS_exec);
  SetPrototypeMethod(isolate, data, t, "backup", JS_backup);
  SetPrototypeMethod(isolate, data, t, "serialize", JS_serialize);
  SetPrototypeMethod(isolate, data, t, "function", JS_function);
  SetPrototypeMethod(isolate, data, t, "aggregate", JS_aggregate);
  SetPrototypeMethod(isolate, data, t, "table", JS_table);
  SetPrototypeMethod(isolate, data, t, "close", JS_close);
  SetPrototypeMethod(isolate, data, t, "defaultSafeIntegers",
                     JS_defaultSafeIntegers);
  SetPrototypeMethod(isolate, data, t, "unsafeMode", JS_unsafeMode);
  SetPrototypeMethod(isolate, data, t, "createFTS5Tokenizer",
                     JS_createFTS5Tokenizer);
  SetPrototypeMethod(isolate, data, t, "signalTokenize", JS_signalTokenize);
  SetPrototypeGetter(isolate, data, t, "open", JS_open);
  SetPrototypeGetter(isolate, data, t, "inTransaction", JS_inTransaction);
  return t->GetFunction(isolate->GetCurrentContext()).ToLocalChecked();
}
bool Database::CompareDatabase::operator()(Database const* const a,
                                           Database const* const b) const {
  return a < b;
}
bool Database::CompareStatement::operator()(Statement const* const a,
                                            Statement const* const b) const {
  return Statement::Compare(a, b);
}
bool Database::CompareBackup::operator()(Backup const* const a,
                                         Backup const* const b) const {
  return Backup::Compare(a, b);
}
void Database::ThrowDatabaseError() {
  if (was_js_error)
    was_js_error = false;
  else
    ThrowSqliteError(addon, db_handle);
}
void Database::ThrowSqliteError(Addon* addon, sqlite3* db_handle) {
  assert(db_handle != NULL);
  ThrowSqliteError(addon, sqlite3_errmsg(db_handle),
                   sqlite3_extended_errcode(db_handle));
}
void Database::ThrowSqliteError(Addon* addon, char const* message, int code) {
  assert(message != NULL);
  assert((code & 0xff) != SQLITE_OK);
  assert((code & 0xff) != SQLITE_ROW);
  assert((code & 0xff) != SQLITE_DONE);
  v8 ::Isolate* isolate = v8 ::Isolate ::GetCurrent();
  v8::Local<v8::Value> args[2] = {StringFromUtf8(isolate, message, -1),
                                  addon->cs.Code(isolate, code)};
  isolate->ThrowException(
      addon->SqliteError.Get(isolate)
          ->NewInstance(isolate->GetCurrentContext(), 2, args)
          .ToLocalChecked());
}
bool Database::Log(v8::Isolate* isolate, sqlite3_stmt* handle) {
  assert(was_js_error == false);
  if (!has_logger)
    return false;
  char* expanded = sqlite3_expanded_sql(handle);
  v8::Local<v8::Value> arg =
      StringFromUtf8(isolate, expanded ? expanded : sqlite3_sql(handle), -1);
  was_js_error =
      logger.Get(isolate)
          .As<v8::Function>()
          ->Call(isolate->GetCurrentContext(), v8::Undefined(isolate), 1, &arg)
          .IsEmpty();
  if (expanded)
    sqlite3_free(expanded);
  return was_js_error;
}
void Database::CloseHandles() {
  if (open) {
    open = false;
    for (Statement* stmt : stmts)
      stmt->CloseHandles();
    for (Backup* backup : backups)
      backup->CloseHandles();
    stmts.clear();
    backups.clear();
    int status = sqlite3_close(db_handle);
    assert(status == SQLITE_OK);
    ((void)status);
  }
}
Database::~Database() {
  if (open)
    addon->dbs.erase(this);
  CloseHandles();
}
Database::Database(v8::Isolate* isolate,
                   Addon* addon,
                   sqlite3* db_handle,
                   v8::Local<v8::Value> logger)
    : node::ObjectWrap(),
      db_handle(db_handle),
      open(true),
      busy(false),
      safe_ints(false),
      unsafe_mode(false),
      was_js_error(false),
      has_logger(logger->IsFunction()),
      iterators(0),
      addon(addon),
      logger(isolate, logger),
      stmts(),
      backups() {
  assert(db_handle != NULL);
  addon->dbs.insert(this);
}
fts5_api* Database::GetFTS5API() {
  int rc;
  sqlite3_stmt* pStmt = nullptr;

  rc = sqlite3_prepare(db_handle, "SELECT fts5(?1)", -1, &pStmt, 0);
  if (rc != SQLITE_OK) {
    ThrowSqliteError(addon, db_handle);
    return nullptr;
  }

  fts5_api* fts5 = nullptr;
  sqlite3_bind_pointer(pStmt, 1, (void*)&fts5, "fts5_api_ptr", nullptr);
  sqlite3_step(pStmt);
  rc = sqlite3_finalize(pStmt);
  if (rc != SQLITE_OK) {
    ThrowSqliteError(addon, db_handle);
    return nullptr;
  }

  assert(fts5 != nullptr);
  return fts5;
}
void Database::JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  assert(info.IsConstructCall());
  if (info.Length() <= (0) || !info[0]->IsString())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> filename = (info[0].As<v8 ::String>());
  if (info.Length() <= (1) || !info[1]->IsString())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> filenameGiven = (info[1].As<v8 ::String>());
  if (info.Length() <= (2) || !info[2]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "third"
        " argument to be "
        "a boolean");
  bool in_memory = (info[2].As<v8 ::Boolean>())->Value();
  if (info.Length() <= (3) || !info[3]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "fourth"
        " argument to be "
        "a boolean");
  bool readonly = (info[3].As<v8 ::Boolean>())->Value();
  if (info.Length() <= (4) || !info[4]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "fifth"
        " argument to be "
        "a boolean");
  bool must_exist = (info[4].As<v8 ::Boolean>())->Value();
  if (info.Length() <= (5) || !info[5]->IsInt32())
    return ThrowTypeError(
        "Expected "
        "sixth"
        " argument to be "
        "a 32-bit signed integer");
  int timeout = (info[5].As<v8 ::Int32>())->Value();
  if (info.Length() <= (6))
    return ThrowTypeError(
        "Expected a "
        "seventh"
        " argument");
  v8 ::Local<v8 ::Value> logger = info[6];
  if (info.Length() <= (7))
    return ThrowTypeError(
        "Expected a "
        "eighth"
        " argument");
  v8 ::Local<v8 ::Value> buffer = info[7];

  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  v8 ::Isolate* isolate = info.GetIsolate();
  sqlite3* db_handle;
  v8::String::Utf8Value utf8(isolate, filename);
  int mask = readonly     ? SQLITE_OPEN_READONLY
             : must_exist ? SQLITE_OPEN_READWRITE
                          : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

  if (sqlite3_open_v2(*utf8, &db_handle, mask, NULL) != SQLITE_OK) {
    ThrowSqliteError(addon, db_handle);
    int status = sqlite3_close(db_handle);
    assert(status == SQLITE_OK);
    ((void)status);
    return;
  }

  assert(sqlite3_db_mutex(db_handle) == NULL);
  sqlite3_extended_result_codes(db_handle, 1);
  sqlite3_busy_timeout(db_handle, timeout);
  sqlite3_limit(
      db_handle, SQLITE_LIMIT_LENGTH,
      MAX_BUFFER_SIZE < MAX_STRING_SIZE ? MAX_BUFFER_SIZE : MAX_STRING_SIZE);
  sqlite3_limit(db_handle, SQLITE_LIMIT_SQL_LENGTH, MAX_STRING_SIZE);
  int status = sqlite3_db_config(db_handle, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
  assert(status == SQLITE_OK);

  if (node::Buffer::HasInstance(buffer) &&
      !Deserialize(buffer.As<v8::Object>(), addon, db_handle, readonly)) {
    int status = sqlite3_close(db_handle);
    assert(status == SQLITE_OK);
    ((void)status);
    return;
  }

  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
  Database* db = new Database(isolate, addon, db_handle, logger);
  db->Wrap(info.This());
  SetFrozen(isolate, ctx, info.This(), addon->cs.memory,
            v8::Boolean::New(isolate, in_memory));
  SetFrozen(isolate, ctx, info.This(), addon->cs.readonly,
            v8::Boolean::New(isolate, readonly));
  SetFrozen(isolate, ctx, info.This(), addon->cs.name, filenameGiven);

  fts5_api* fts5 = db->GetFTS5API();

  if (fts5 == nullptr) {
    return;
  }
  SignalTokenizerModule* icu = new SignalTokenizerModule();
  fts5->xCreateTokenizer(fts5, "signal_tokenizer", icu, icu->get_api_object(),
                         &SignalTokenizerModule::xDestroy);

  info.GetReturnValue().Set(info.This());
}
void Database::JS_prepare(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  if (info.Length() <= (0) || !info[0]->IsString())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> source = (info[0].As<v8 ::String>());
  if (info.Length() <= (1) || !info[1]->IsObject())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "an object");
  v8 ::Local<v8 ::Object> database = (info[1].As<v8 ::Object>());
  if (info.Length() <= (2) || !info[2]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "third"
        " argument to be "
        "a boolean");
  bool pragmaMode = (info[2].As<v8 ::Boolean>())->Value();
  (void)source;
  (void)database;
  (void)pragmaMode;
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  v8 ::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Function> c = addon->Statement.Get(isolate);
  addon->privileged_info = &info;
  v8::MaybeLocal<v8::Object> maybeStatement =
      c->NewInstance(isolate->GetCurrentContext(), 0, NULL);
  addon->privileged_info = NULL;
  if (!maybeStatement.IsEmpty())
    info.GetReturnValue().Set(maybeStatement.ToLocalChecked());
}
void Database::JS_exec(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() <= (0) || !info[0]->IsString())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> source = (info[0].As<v8 ::String>());
  if (!db->open)
    return ThrowTypeError("The database connection is not open");
  if (db->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (!db->unsafe_mode) {
    if (db->iterators)
      return ThrowTypeError(
          "This database connection is busy executing a query");
  }
  ((void)0);
  db->busy = true;

  v8 ::Isolate* isolate = info.GetIsolate();
  v8::String::Utf8Value utf8(isolate, source);
  const char* sql = *utf8;
  const char* tail;

  int status;
  const bool has_logger = db->has_logger;
  sqlite3* const db_handle = db->db_handle;
  sqlite3_stmt* handle;

  for (;;) {
    while (IS_SKIPPED(*sql))
      ++sql;
    status = sqlite3_prepare_v2(db_handle, sql, -1, &handle, &tail);
    sql = tail;
    if (!handle)
      break;
    if (has_logger && db->Log(isolate, handle)) {
      sqlite3_finalize(handle);
      status = -1;
      break;
    }
    do
      status = sqlite3_step(handle);
    while (status == SQLITE_ROW);
    status = sqlite3_finalize(handle);
    if (status != SQLITE_OK)
      break;
  }

  db->busy = false;
  if (status != SQLITE_OK) {
    db->ThrowDatabaseError();
  }
}
void Database::JS_backup(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  if (info.Length() <= (0) || !info[0]->IsObject())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "an object");
  v8 ::Local<v8 ::Object> database = (info[0].As<v8 ::Object>());
  if (info.Length() <= (1) || !info[1]->IsString())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> attachedName = (info[1].As<v8 ::String>());
  if (info.Length() <= (2) || !info[2]->IsString())
    return ThrowTypeError(
        "Expected "
        "third"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> destFile = (info[2].As<v8 ::String>());
  if (info.Length() <= (3) || !info[3]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "fourth"
        " argument to be "
        "a boolean");
  bool unlink = (info[3].As<v8 ::Boolean>())->Value();
  (void)database;
  (void)attachedName;
  (void)destFile;
  (void)unlink;
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  v8 ::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Function> c = addon->Backup.Get(isolate);
  addon->privileged_info = &info;
  v8::MaybeLocal<v8::Object> maybeBackup =
      c->NewInstance(isolate->GetCurrentContext(), 0, NULL);
  addon->privileged_info = NULL;
  if (!maybeBackup.IsEmpty())
    info.GetReturnValue().Set(maybeBackup.ToLocalChecked());
}
void Database::JS_serialize(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() <= (0) || !info[0]->IsString())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> attachedName = (info[0].As<v8 ::String>());
  if (!db->open)
    return ThrowTypeError("The database connection is not open");
  if (db->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (db->iterators)
    return ThrowTypeError("This database connection is busy executing a query");

  v8 ::Isolate* isolate = info.GetIsolate();
  v8::String::Utf8Value attached_name(isolate, attachedName);
  sqlite3_int64 length = -1;
  unsigned char* data =
      sqlite3_serialize(db->db_handle, *attached_name, &length, 0);

  if (!data && length) {
    ThrowError("Out of memory");
    return;
  }

  info.GetReturnValue().Set(node::Buffer::New(isolate,
                                              reinterpret_cast<char*>(data),
                                              length, FreeSerialization, NULL)
                                .ToLocalChecked());
}
void Database::JS_function(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() <= (0) || !info[0]->IsFunction())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a function");
  v8 ::Local<v8 ::Function> fn = (info[0].As<v8 ::Function>());
  if (info.Length() <= (1) || !info[1]->IsString())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> nameString = (info[1].As<v8 ::String>());
  if (info.Length() <= (2) || !info[2]->IsInt32())
    return ThrowTypeError(
        "Expected "
        "third"
        " argument to be "
        "a 32-bit signed integer");
  int argc = (info[2].As<v8 ::Int32>())->Value();
  if (info.Length() <= (3) || !info[3]->IsInt32())
    return ThrowTypeError(
        "Expected "
        "fourth"
        " argument to be "
        "a 32-bit signed integer");
  int safe_ints = (info[3].As<v8 ::Int32>())->Value();
  if (info.Length() <= (4) || !info[4]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "fifth"
        " argument to be "
        "a boolean");
  bool deterministic = (info[4].As<v8 ::Boolean>())->Value();
  if (info.Length() <= (5) || !info[5]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "sixth"
        " argument to be "
        "a boolean");
  bool direct_only = (info[5].As<v8 ::Boolean>())->Value();
  if (!db->open)
    return ThrowTypeError("The database connection is not open");
  if (db->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (db->iterators)
    return ThrowTypeError("This database connection is busy executing a query");

  v8 ::Isolate* isolate = info.GetIsolate();
  v8::String::Utf8Value name(isolate, nameString);
  int mask = SQLITE_UTF8;
  if (deterministic)
    mask |= SQLITE_DETERMINISTIC;
  if (direct_only)
    mask |= SQLITE_DIRECTONLY;
  safe_ints = safe_ints < 2 ? safe_ints : static_cast<int>(db->safe_ints);

  if (sqlite3_create_function_v2(
          db->db_handle, *name, argc, mask,
          new CustomFunction(isolate, db, *name, fn, safe_ints),
          CustomFunction::xFunc, NULL, NULL,
          CustomFunction::xDestroy) != SQLITE_OK) {
    db->ThrowDatabaseError();
  }
}
void Database::JS_aggregate(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() <= (0))
    return ThrowTypeError(
        "Expected a "
        "first"
        " argument");
  v8 ::Local<v8 ::Value> start = info[0];
  if (info.Length() <= (1) || !info[1]->IsFunction())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "a function");
  v8 ::Local<v8 ::Function> step = (info[1].As<v8 ::Function>());
  if (info.Length() <= (2))
    return ThrowTypeError(
        "Expected a "
        "third"
        " argument");
  v8 ::Local<v8 ::Value> inverse = info[2];
  if (info.Length() <= (3))
    return ThrowTypeError(
        "Expected a "
        "fourth"
        " argument");
  v8 ::Local<v8 ::Value> result = info[3];
  if (info.Length() <= (4) || !info[4]->IsString())
    return ThrowTypeError(
        "Expected "
        "fifth"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> nameString = (info[4].As<v8 ::String>());
  if (info.Length() <= (5) || !info[5]->IsInt32())
    return ThrowTypeError(
        "Expected "
        "sixth"
        " argument to be "
        "a 32-bit signed integer");
  int argc = (info[5].As<v8 ::Int32>())->Value();
  if (info.Length() <= (6) || !info[6]->IsInt32())
    return ThrowTypeError(
        "Expected "
        "seventh"
        " argument to be "
        "a 32-bit signed integer");
  int safe_ints = (info[6].As<v8 ::Int32>())->Value();
  if (info.Length() <= (7) || !info[7]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "eighth"
        " argument to be "
        "a boolean");
  bool deterministic = (info[7].As<v8 ::Boolean>())->Value();
  if (info.Length() <= (8) || !info[8]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "ninth"
        " argument to be "
        "a boolean");
  bool direct_only = (info[8].As<v8 ::Boolean>())->Value();
  if (!db->open)
    return ThrowTypeError("The database connection is not open");
  if (db->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (db->iterators)
    return ThrowTypeError("This database connection is busy executing a query");

  v8 ::Isolate* isolate = info.GetIsolate();
  v8::String::Utf8Value name(isolate, nameString);
  auto xInverse = inverse->IsFunction() ? CustomAggregate::xInverse : NULL;
  auto xValue = xInverse ? CustomAggregate::xValue : NULL;
  int mask = SQLITE_UTF8;
  if (deterministic)
    mask |= SQLITE_DETERMINISTIC;
  if (direct_only)
    mask |= SQLITE_DIRECTONLY;
  safe_ints = safe_ints < 2 ? safe_ints : static_cast<int>(db->safe_ints);

  if (sqlite3_create_window_function(
          db->db_handle, *name, argc, mask,
          new CustomAggregate(isolate, db, *name, start, step, inverse, result,
                              safe_ints),
          CustomAggregate::xStep, CustomAggregate::xFinal, xValue, xInverse,
          CustomAggregate::xDestroy) != SQLITE_OK) {
    db->ThrowDatabaseError();
  }
}
void Database::JS_table(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() <= (0) || !info[0]->IsFunction())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a function");
  v8 ::Local<v8 ::Function> factory = (info[0].As<v8 ::Function>());
  if (info.Length() <= (1) || !info[1]->IsString())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> nameString = (info[1].As<v8 ::String>());
  if (info.Length() <= (2) || !info[2]->IsBoolean())
    return ThrowTypeError(
        "Expected "
        "third"
        " argument to be "
        "a boolean");
  bool eponymous = (info[2].As<v8 ::Boolean>())->Value();
  if (!db->open)
    return ThrowTypeError("The database connection is not open");
  if (db->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (db->iterators)
    return ThrowTypeError("This database connection is busy executing a query");

  v8 ::Isolate* isolate = info.GetIsolate();
  v8::String::Utf8Value name(isolate, nameString);
  sqlite3_module* module =
      eponymous ? &CustomTable::EPONYMOUS_MODULE : &CustomTable::MODULE;

  db->busy = true;
  if (sqlite3_create_module_v2(db->db_handle, *name, module,
                               new CustomTable(isolate, db, *name, factory),
                               CustomTable::Destructor) != SQLITE_OK) {
    db->ThrowDatabaseError();
  }
  db->busy = false;
}
void Database::JS_close(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (db->open) {
    if (db->busy)
      return ThrowTypeError(
          "This database connection is busy executing a query");
    if (db->iterators)
      return ThrowTypeError(
          "This database connection is busy executing a query");
    db->addon->dbs.erase(db);
    db->CloseHandles();
  }
}
void Database::JS_defaultSafeIntegers(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() == 0)
    db->safe_ints = true;
  else {
    if (info.Length() <= (0) || !info[0]->IsBoolean())
      return ThrowTypeError(
          "Expected "
          "first"
          " argument to be "
          "a boolean");
    db->safe_ints = (info[0].As<v8 ::Boolean>())->Value();
  }
}
void Database::JS_unsafeMode(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() == 0)
    db->unsafe_mode = true;
  else {
    if (info.Length() <= (0) || !info[0]->IsBoolean())
      return ThrowTypeError(
          "Expected "
          "first"
          " argument to be "
          "a boolean");
    db->unsafe_mode = (info[0].As<v8 ::Boolean>())->Value();
  }
  sqlite3_db_config(db->db_handle, SQLITE_DBCONFIG_DEFENSIVE,
                    static_cast<int>(!db->unsafe_mode), NULL);
}
void Database::JS_createFTS5Tokenizer(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  v8 ::Isolate* isolate = info.GetIsolate();

  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  if (info.Length() <= (0) || !info[0]->IsString())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> name = (info[0].As<v8 ::String>());
  if (info.Length() <= (1) || !info[1]->IsFunction())
    return ThrowTypeError(
        "Expected "
        "second"
        " argument to be "
        "a function");
  v8 ::Local<v8 ::Function> create_instance_fn = (info[1].As<v8 ::Function>());

  TokenizerModule* t = new TokenizerModule(isolate, create_instance_fn);

  v8::String::Utf8Value utf8(isolate, name);
  fts5_api* fts5 = db->GetFTS5API();

  if (fts5 == nullptr) {
    return;
  }
  fts5->xCreateTokenizer(fts5, *utf8, t, t->get_api_object(),
                         &TokenizerModule::xDestroy);
}
int Database::SignalTokenizeCallback(void* tokensPtr,
                                     int _flags,
                                     char const* token,
                                     int len,
                                     int _start,
                                     int _end) {
  std::vector<std::string>* tokens =
      reinterpret_cast<std::vector<std::string>*>(tokensPtr);
  tokens->push_back(std::string(token, len));
  return SQLITE_OK;
}
void Database::JS_signalTokenize(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  v8 ::Isolate* isolate = info.GetIsolate();
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  if (info.Length() <= (0) || !info[0]->IsString())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a string");
  v8 ::Local<v8 ::String> value = (info[0].As<v8 ::String>());

  v8::String::Utf8Value utf8(isolate, value);

  std::vector<std::string> tokens;
  int status =
      signal_fts5_tokenize(nullptr, reinterpret_cast<void*>(&tokens), 0, *utf8,
                           utf8.length(), SignalTokenizeCallback);
  if (status != SQLITE_OK) {
    ThrowSqliteError(addon, "Enable to tokenize string", status);
    return;
  }

  v8::Local<v8::Array> result = v8::Array::New(isolate);

  int i = 0;
  for (auto& str : tokens) {
    result->Set(ctx, i++, StringFromUtf8(isolate, str.c_str(), str.length()))
        .FromJust();
  }

  info.GetReturnValue().Set(result);
}
void Database::JS_open(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  info.GetReturnValue().Set(
      node ::ObjectWrap ::Unwrap<Database>(info.This())->open);
}
void Database::JS_inTransaction(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Database* db = node ::ObjectWrap ::Unwrap<Database>(info.This());
  info.GetReturnValue().Set(
      db->open && !static_cast<bool>(sqlite3_get_autocommit(db->db_handle)));
}
bool Database::Deserialize(v8::Local<v8::Object> buffer,
                           Addon* addon,
                           sqlite3* db_handle,
                           bool readonly) {
  size_t length = node::Buffer::Length(buffer);
  unsigned char* data = (unsigned char*)sqlite3_malloc64(length);
  unsigned int flags =
      SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE;

  if (readonly) {
    flags |= SQLITE_DESERIALIZE_READONLY;
  }
  if (length) {
    if (!data) {
      ThrowError("Out of memory");
      return false;
    }
    memcpy(data, node::Buffer::Data(buffer), length);
  }

  int status =
      sqlite3_deserialize(db_handle, "main", data, length, length, flags);
  if (status != SQLITE_OK) {
    ThrowSqliteError(addon,
                     status == SQLITE_ERROR ? "unable to deserialize database"
                                            : sqlite3_errstr(status),
                     status);
    return false;
  }

  return true;
}
void Database::FreeSerialization(char* data, void* _) {
  sqlite3_free(data);
}
int const Database::MAX_BUFFER_SIZE;
int const Database::MAX_STRING_SIZE;
v8::Local<v8 ::Function> Statement::Init(v8::Isolate* isolate,
                                         v8::Local<v8 ::External> data) {
  v8::Local<v8::FunctionTemplate> t =
      NewConstructorTemplate(isolate, data, JS_new, "Statement");
  SetPrototypeMethod(isolate, data, t, "run", JS_run);
  SetPrototypeMethod(isolate, data, t, "get", JS_get);
  SetPrototypeMethod(isolate, data, t, "all", JS_all);
  SetPrototypeMethod(isolate, data, t, "iterate", JS_iterate);
  SetPrototypeMethod(isolate, data, t, "bind", JS_bind);
  SetPrototypeMethod(isolate, data, t, "pluck", JS_pluck);
  SetPrototypeMethod(isolate, data, t, "expand", JS_expand);
  SetPrototypeMethod(isolate, data, t, "raw", JS_raw);
  SetPrototypeMethod(isolate, data, t, "safeIntegers", JS_safeIntegers);
  SetPrototypeMethod(isolate, data, t, "columns", JS_columns);
  SetPrototypeGetter(isolate, data, t, "busy", JS_busy);
  return t->GetFunction(isolate->GetCurrentContext()).ToLocalChecked();
}
BindMap* Statement::GetBindMap(v8::Isolate* isolate) {
  if (has_bind_map)
    return &extras->bind_map;
  BindMap* bind_map = &extras->bind_map;
  int param_count = sqlite3_bind_parameter_count(handle);
  for (int i = 1; i <= param_count; ++i) {
    const char* name = sqlite3_bind_parameter_name(handle, i);
    if (name != NULL)
      bind_map->Add(isolate, name + 1, i);
  }
  has_bind_map = true;
  return bind_map;
}
void Statement::CloseHandles() {
  if (alive) {
    alive = false;
    sqlite3_finalize(handle);
  }
}
Statement::~Statement() {
  if (alive)
    db->RemoveStatement(this);
  CloseHandles();
  delete extras;
}
Statement::Extras::Extras(sqlite3_uint64 id) : bind_map(0), id(id) {}
Statement::Statement(Database* db,
                     sqlite3_stmt* handle,
                     sqlite3_uint64 id,
                     bool returns_data)
    : node::ObjectWrap(),
      db(db),
      handle(handle),
      extras(new Extras(id)),
      alive(true),
      locked(false),
      bound(false),
      has_bind_map(false),
      safe_ints(db->GetState()->safe_ints),
      mode(Data::FLAT),
      returns_data(returns_data) {
  assert(db != NULL);
  assert(handle != NULL);
  assert(db->GetState()->open);
  assert(!db->GetState()->busy);
  db->AddStatement(this);
}
void Statement::JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  if (!addon->privileged_info) {
    return ThrowTypeError(
        "Statements can only be constructed by the db.prepare() method");
  }
  assert(info.IsConstructCall());
  Database* db =
      node ::ObjectWrap ::Unwrap<Database>(addon->privileged_info->This());
  if (!db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");

  v8::Local<v8::String> source = (*addon->privileged_info)[0].As<v8::String>();
  v8::Local<v8::Object> database =
      (*addon->privileged_info)[1].As<v8::Object>();
  bool pragmaMode = (*addon->privileged_info)[2].As<v8::Boolean>()->Value();
  int flags = SQLITE_PREPARE_PERSISTENT;

  if (pragmaMode) {
    if (!db->GetState()->unsafe_mode) {
      if (db->GetState()->iterators)
        return ThrowTypeError(
            "This database connection is busy executing a query");
    }
    ((void)0);
    flags = 0;
  }

  v8 ::Isolate* isolate = info.GetIsolate();
  v8::String::Utf8Value utf8(isolate, source);
  sqlite3_stmt* handle;
  const char* tail;

  if (sqlite3_prepare_v3(db->GetHandle(), *utf8, utf8.length() + 1, flags,
                         &handle, &tail) != SQLITE_OK) {
    return db->ThrowDatabaseError();
  }
  if (handle == NULL) {
    return ThrowRangeError("The supplied SQL string contains no statements");
  }
  for (char c; (c = *tail); ++tail) {
    if (IS_SKIPPED(c))
      continue;
    if (c == '/' && tail[1] == '*') {
      tail += 2;
      for (char c; (c = *tail); ++tail) {
        if (c == '*' && tail[1] == '/') {
          tail += 1;
          break;
        }
      }
    } else if (c == '-' && tail[1] == '-') {
      tail += 2;
      for (char c; (c = *tail); ++tail) {
        if (c == '\n')
          break;
      }
    } else {
      sqlite3_finalize(handle);
      return ThrowRangeError(
          "The supplied SQL string contains more than one statement");
    }
  }

  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
  bool returns_data = sqlite3_column_count(handle) >= 1 || pragmaMode;
  Statement* stmt = new Statement(db, handle, addon->NextId(), returns_data);
  stmt->Wrap(info.This());
  SetFrozen(isolate, ctx, info.This(), addon->cs.reader,
            v8::Boolean::New(isolate, returns_data));
  SetFrozen(isolate, ctx, info.This(), addon->cs.readonly,
            v8::Boolean::New(isolate, sqlite3_stmt_readonly(handle) != 0));
  SetFrozen(isolate, ctx, info.This(), addon->cs.source, source);
  SetFrozen(isolate, ctx, info.This(), addon->cs.database, database);

  info.GetReturnValue().Set(info.This());
}
void Statement::JS_run(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  ((void)0);
  sqlite3_stmt* handle = stmt->handle;
  Database* db = stmt->db;
  if (!db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  if (!db->GetState()->unsafe_mode) {
    if (db->GetState()->iterators)
      return ThrowTypeError(
          "This database connection is busy executing a query");
  }
  ((void)0);
  const bool bound = stmt->bound;
  if (!bound) {
    Binder binder(handle);
    if (!binder.Bind(info, info.Length(), stmt)) {
      sqlite3_clear_bindings(handle);
      return;
    }
    ((void)0);
  } else if (info.Length() > 0) {
    return ThrowTypeError("This statement already has bound parameters");
  }
  ((void)0);
  db->GetState()->busy = true;
  v8 ::Isolate* isolate = info.GetIsolate();
  if (db->Log(isolate, handle)) {
    db->GetState()->busy = false;
    db->ThrowDatabaseError();
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  }
  ((void)0);
  sqlite3* db_handle = db->GetHandle();
  int total_changes_before = sqlite3_total_changes(db_handle);

  sqlite3_step(handle);
  if (sqlite3_reset(handle) == SQLITE_OK) {
    int changes = sqlite3_total_changes(db_handle) == total_changes_before
                      ? 0
                      : sqlite3_changes(db_handle);
    sqlite3_int64 id = sqlite3_last_insert_rowid(db_handle);
    Addon* addon = db->GetAddon();
    v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
    v8::Local<v8::Object> result = v8::Object::New(isolate);
    result
        ->Set(ctx, addon->cs.changes.Get(isolate),
              v8::Int32::New(isolate, changes))
        .FromJust();
    result
        ->Set(ctx, addon->cs.lastInsertRowid.Get(isolate),
              stmt->safe_ints
                  ? v8::BigInt::New(isolate, id).As<v8::Value>()
                  : v8::Number::New(isolate, (double)id).As<v8::Value>())
        .FromJust();
    db->GetState()->busy = false;
    info.GetReturnValue().Set(result);
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  }
  db->GetState()->busy = false;
  db->ThrowDatabaseError();
  if (!bound) {
    sqlite3_clear_bindings(handle);
  }
  return;
}
void Statement::JS_get(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (!stmt->returns_data)
    return ThrowTypeError(
        "This statement does not return data. Use run() instead");
  sqlite3_stmt* handle = stmt->handle;
  Database* db = stmt->db;
  if (!db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  const bool bound = stmt->bound;
  if (!bound) {
    Binder binder(handle);
    if (!binder.Bind(info, info.Length(), stmt)) {
      sqlite3_clear_bindings(handle);
      return;
    }
    ((void)0);
  } else if (info.Length() > 0) {
    return ThrowTypeError("This statement already has bound parameters");
  }
  ((void)0);
  db->GetState()->busy = true;
  v8 ::Isolate* isolate = info.GetIsolate();
  if (db->Log(isolate, handle)) {
    db->GetState()->busy = false;
    db->ThrowDatabaseError();
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  }
  ((void)0);
  int status = sqlite3_step(handle);
  if (status == SQLITE_ROW) {
#ifdef V8_HAS_LOCAL_VECTOR
    v8::LocalVector<v8::Name> keys(isolate);
    v8::Local<v8::Value> result =
        Data::GetRowJS(isolate, isolate->GetCurrentContext(), handle,
                       stmt->safe_ints, stmt->mode, keys);
#else  // !V8_HAS_LOCAL_VECTOR
    v8::Local<v8::Value> result =
        Data::GetRowJS(isolate, isolate->GetCurrentContext(), handle,
                       stmt->safe_ints, stmt->mode);
#endif
    sqlite3_reset(handle);
    db->GetState()->busy = false;
    info.GetReturnValue().Set(result);
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  } else if (status == SQLITE_DONE) {
    sqlite3_reset(handle);
    db->GetState()->busy = false;
    info.GetReturnValue().Set(v8 ::Undefined(isolate));
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  }
  sqlite3_reset(handle);
  db->GetState()->busy = false;
  db->ThrowDatabaseError();
  if (!bound) {
    sqlite3_clear_bindings(handle);
  }
  return;
}
void Statement::JS_all(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (!stmt->returns_data)
    return ThrowTypeError(
        "This statement does not return data. Use run() instead");
  sqlite3_stmt* handle = stmt->handle;
  Database* db = stmt->db;
  if (!db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  const bool bound = stmt->bound;
  if (!bound) {
    Binder binder(handle);
    if (!binder.Bind(info, info.Length(), stmt)) {
      sqlite3_clear_bindings(handle);
      return;
    }
    ((void)0);
  } else if (info.Length() > 0) {
    return ThrowTypeError("This statement already has bound parameters");
  }
  ((void)0);
  db->GetState()->busy = true;
  v8 ::Isolate* isolate = info.GetIsolate();
  if (db->Log(isolate, handle)) {
    db->GetState()->busy = false;
    db->ThrowDatabaseError();
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  }
  ((void)0);
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
  v8::Local<v8::Array> result = v8::Array::New(isolate, 0);
  uint32_t row_count = 0;
  const bool safe_ints = stmt->safe_ints;
  const char mode = stmt->mode;
  bool js_error = false;
#ifdef V8_HAS_LOCAL_VECTOR
  v8::LocalVector<v8::Name> keys(isolate);
#endif  // V8_HAS_LOCAL_VECTOR

  while (sqlite3_step(handle) == SQLITE_ROW) {
    if (row_count == 0xffffffff) {
      ThrowRangeError("Array overflow (too many rows returned)");
      js_error = true;
      break;
    }
#ifdef V8_HAS_LOCAL_VECTOR
    v8::Local<v8::Value> row =
        Data::GetRowJS(isolate, ctx, handle, safe_ints, mode, keys);
#else  // !V8_HAS_LOCAL_VECTOR
    v8::Local<v8::Value> row =
        Data::GetRowJS(isolate, ctx, handle, safe_ints, mode);
#endif
    result->Set(ctx, row_count++, row).FromJust();
  }

  if (sqlite3_reset(handle) == SQLITE_OK && !js_error) {
    db->GetState()->busy = false;
    info.GetReturnValue().Set(result);
    if (!bound) {
      sqlite3_clear_bindings(handle);
    }
    return;
  }
  if (js_error)
    db->GetState()->was_js_error = true;
  db->GetState()->busy = false;
  db->ThrowDatabaseError();
  if (!bound) {
    sqlite3_clear_bindings(handle);
  }
  return;
}
void Statement::JS_iterate(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  v8 ::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Function> c = addon->StatementIterator.Get(isolate);
  addon->privileged_info = &info;
  v8::MaybeLocal<v8::Object> maybeIterator =
      c->NewInstance(isolate->GetCurrentContext(), 0, NULL);
  addon->privileged_info = NULL;
  if (!maybeIterator.IsEmpty())
    info.GetReturnValue().Set(maybeIterator.ToLocalChecked());
}
void Statement::JS_bind(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (stmt->bound)
    return ThrowTypeError(
        "The bind() method can only be invoked once per statement object");
  if (!stmt->db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (stmt->db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  Binder binder(stmt->handle);
  if (!binder.Bind(info, info.Length(), stmt)) {
    sqlite3_clear_bindings(stmt->handle);
    return;
  }
  ((void)0);
  stmt->bound = true;
  info.GetReturnValue().Set(info.This());
}
void Statement::JS_pluck(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (!stmt->returns_data)
    return ThrowTypeError(
        "The pluck() method is only for statements that return data");
  if (stmt->db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  bool use = true;
  if (info.Length() != 0) {
    if (info.Length() <= (0) || !info[0]->IsBoolean())
      return ThrowTypeError(
          "Expected "
          "first"
          " argument to be "
          "a boolean");
    use = (info[0].As<v8 ::Boolean>())->Value();
  }
  stmt->mode = use                         ? Data::PLUCK
               : stmt->mode == Data::PLUCK ? Data::FLAT
                                           : stmt->mode;
  info.GetReturnValue().Set(info.This());
}
void Statement::JS_expand(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (!stmt->returns_data)
    return ThrowTypeError(
        "The expand() method is only for statements that return data");
  if (stmt->db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  bool use = true;
  if (info.Length() != 0) {
    if (info.Length() <= (0) || !info[0]->IsBoolean())
      return ThrowTypeError(
          "Expected "
          "first"
          " argument to be "
          "a boolean");
    use = (info[0].As<v8 ::Boolean>())->Value();
  }
  stmt->mode = use                          ? Data::EXPAND
               : stmt->mode == Data::EXPAND ? Data::FLAT
                                            : stmt->mode;
  info.GetReturnValue().Set(info.This());
}
void Statement::JS_raw(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (!stmt->returns_data)
    return ThrowTypeError(
        "The raw() method is only for statements that return data");
  if (stmt->db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  bool use = true;
  if (info.Length() != 0) {
    if (info.Length() <= (0) || !info[0]->IsBoolean())
      return ThrowTypeError(
          "Expected "
          "first"
          " argument to be "
          "a boolean");
    use = (info[0].As<v8 ::Boolean>())->Value();
  }
  stmt->mode = use                       ? Data::RAW
               : stmt->mode == Data::RAW ? Data::FLAT
                                         : stmt->mode;
  info.GetReturnValue().Set(info.This());
}
void Statement::JS_safeIntegers(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (stmt->db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (stmt->locked)
    return ThrowTypeError("This statement is busy executing a query");
  if (info.Length() == 0)
    stmt->safe_ints = true;
  else {
    if (info.Length() <= (0) || !info[0]->IsBoolean())
      return ThrowTypeError(
          "Expected "
          "first"
          " argument to be "
          "a boolean");
    stmt->safe_ints = (info[0].As<v8 ::Boolean>())->Value();
  }
  info.GetReturnValue().Set(info.This());
}
void Statement::JS_columns(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  if (!stmt->returns_data)
    return ThrowTypeError(
        "The columns() method is only for statements that return data");
  if (!stmt->db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (stmt->db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  Addon* addon = stmt->db->GetAddon();
  v8 ::Isolate* isolate = info.GetIsolate();
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  int column_count = sqlite3_column_count(stmt->handle);
  v8::Local<v8::Array> columns = v8::Array::New(isolate);

  v8::Local<v8::String> name = addon->cs.name.Get(isolate);
  v8::Local<v8::String> columnName = addon->cs.column.Get(isolate);
  v8::Local<v8::String> tableName = addon->cs.table.Get(isolate);
  v8::Local<v8::String> databaseName = addon->cs.database.Get(isolate);
  v8::Local<v8::String> typeName = addon->cs.type.Get(isolate);

  for (int i = 0; i < column_count; ++i) {
    v8::Local<v8::Object> column = v8::Object::New(isolate);

    column
        ->Set(ctx, name,
              InternalizedFromUtf8OrNull(
                  isolate, sqlite3_column_name(stmt->handle, i), -1))
        .FromJust();
    column
        ->Set(ctx, columnName,
              InternalizedFromUtf8OrNull(
                  isolate, sqlite3_column_origin_name(stmt->handle, i), -1))
        .FromJust();
    column
        ->Set(ctx, tableName,
              InternalizedFromUtf8OrNull(
                  isolate, sqlite3_column_table_name(stmt->handle, i), -1))
        .FromJust();
    column
        ->Set(ctx, databaseName,
              InternalizedFromUtf8OrNull(
                  isolate, sqlite3_column_database_name(stmt->handle, i), -1))
        .FromJust();
    column
        ->Set(ctx, typeName,
              InternalizedFromUtf8OrNull(
                  isolate, sqlite3_column_decltype(stmt->handle, i), -1))
        .FromJust();

    columns->Set(ctx, i, column).FromJust();
  }

  info.GetReturnValue().Set(columns);
}
void Statement::JS_busy(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
  info.GetReturnValue().Set(stmt->alive && stmt->locked);
}
v8::Local<v8 ::Function> StatementIterator::Init(
    v8::Isolate* isolate,
    v8::Local<v8 ::External> data) {
  v8::Local<v8::FunctionTemplate> t =
      NewConstructorTemplate(isolate, data, JS_new, "StatementIterator");
  SetPrototypeMethod(isolate, data, t, "next", JS_next);
  SetPrototypeMethod(isolate, data, t, "return", JS_return);
  SetPrototypeSymbolMethod(isolate, data, t, v8::Symbol::GetIterator(isolate),
                           JS_symbolIterator);
  return t->GetFunction(isolate->GetCurrentContext()).ToLocalChecked();
}
StatementIterator::~StatementIterator() {}
StatementIterator::StatementIterator(Statement* stmt, bool bound)
    : node::ObjectWrap(),
      stmt(stmt),
      handle(stmt->handle),
      db_state(stmt->db->GetState()),
      bound(bound),
      safe_ints(stmt->safe_ints),
      mode(stmt->mode),
      alive(true),
      logged(!db_state->has_logger) {
  assert(stmt != NULL);
  assert(handle != NULL);
  assert(stmt->bound == bound);
  assert(stmt->alive == true);
  assert(stmt->locked == false);
  assert(db_state->iterators < USHRT_MAX);
  stmt->locked = true;
  db_state->iterators += 1;
}
void StatementIterator::JS_new(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  if (!addon->privileged_info)
    return ThrowTypeError("Disabled constructor");
  assert(info.IsConstructCall());

  StatementIterator* iter;
  {
    const v8 ::FunctionCallbackInfo<v8 ::Value>& info = *addon->privileged_info;
    Statement* stmt = node ::ObjectWrap ::Unwrap<Statement>(info.This());
    if (!stmt->returns_data)
      return ThrowTypeError(
          "This statement does not return data. Use run() instead");
    sqlite3_stmt* handle = stmt->handle;
    Database* db = stmt->db;
    if (!db->GetState()->open)
      return ThrowTypeError("The database connection is not open");
    if (db->GetState()->busy)
      return ThrowTypeError(
          "This database connection is busy executing a query");
    if (stmt->locked)
      return ThrowTypeError("This statement is busy executing a query");
    if (db->GetState()->iterators == USHRT_MAX)
      return ThrowRangeError("Too many active database iterators");
    const bool bound = stmt->bound;
    if (!bound) {
      Binder binder(handle);
      if (!binder.Bind(info, info.Length(), stmt)) {
        sqlite3_clear_bindings(handle);
        return;
      }
      ((void)0);
    } else if (info.Length() > 0) {
      return ThrowTypeError("This statement already has bound parameters");
    }
    ((void)0);
    iter = new StatementIterator(stmt, bound);
  }
  v8 ::Isolate* isolate = info.GetIsolate();
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
  iter->Wrap(info.This());
  SetFrozen(isolate, ctx, info.This(), addon->cs.statement,
            addon->privileged_info->This());

  info.GetReturnValue().Set(info.This());
}
void StatementIterator::JS_next(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  StatementIterator* iter =
      node ::ObjectWrap ::Unwrap<StatementIterator>(info.This());
  if (iter->db_state->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (iter->alive)
    iter->Next(info);
  else
    info.GetReturnValue().Set(
        DoneRecord(info.GetIsolate(), iter->db_state->addon));
}
void StatementIterator::JS_return(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  StatementIterator* iter =
      node ::ObjectWrap ::Unwrap<StatementIterator>(info.This());
  if (iter->db_state->busy)
    return ThrowTypeError("This database connection is busy executing a query");
  if (iter->alive)
    iter->Return(info);
  else
    info.GetReturnValue().Set(
        DoneRecord(info.GetIsolate(), iter->db_state->addon));
}
void StatementIterator::JS_symbolIterator(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  info.GetReturnValue().Set(info.This());
}
void StatementIterator::Next(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  assert(alive == true);
  db_state->busy = true;
  if (!logged) {
    logged = true;
    if (stmt->db->Log(info.GetIsolate(), handle)) {
      db_state->busy = false;
      Throw();
      return;
    }
  }
  int status = sqlite3_step(handle);
  db_state->busy = false;
  if (status == SQLITE_ROW) {
    v8 ::Isolate* isolate = info.GetIsolate();
    v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
#ifdef V8_HAS_LOCAL_VECTOR
    v8::LocalVector<v8::Name> keys(isolate);
    v8::Local<v8::Value> row =
        Data::GetRowJS(isolate, ctx, handle, safe_ints, mode, keys);
#else  // !V8_HAS_LOCAL_VECTOR
    v8::Local<v8::Value> row =
        Data::GetRowJS(isolate, ctx, handle, safe_ints, mode);
#endif

    info.GetReturnValue().Set(
        NewRecord(isolate, ctx, row, db_state->addon, false));
  } else {
    if (status == SQLITE_DONE)
      Return(info);
    else
      Throw();
  }
}
void StatementIterator::Return(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Cleanup();
  info.GetReturnValue().Set(DoneRecord(info.GetIsolate(), db_state->addon));
  if (!bound) {
    sqlite3_clear_bindings(handle);
  }
  return;
}
void StatementIterator::Throw() {
  Cleanup();
  Database* db = stmt->db;
  db->ThrowDatabaseError();
  if (!bound) {
    sqlite3_clear_bindings(handle);
  }
  return;
}
void StatementIterator::Cleanup() {
  assert(alive == true);
  alive = false;
  stmt->locked = false;
  db_state->iterators -= 1;
  sqlite3_reset(handle);
}
v8::Local<v8 ::Function> Backup::Init(v8::Isolate* isolate,
                                      v8::Local<v8 ::External> data) {
  v8::Local<v8::FunctionTemplate> t =
      NewConstructorTemplate(isolate, data, JS_new, "Backup");
  SetPrototypeMethod(isolate, data, t, "transfer", JS_transfer);
  SetPrototypeMethod(isolate, data, t, "close", JS_close);
  return t->GetFunction(isolate->GetCurrentContext()).ToLocalChecked();
}
void Backup::CloseHandles() {
  if (alive) {
    alive = false;
    std::string filename(sqlite3_db_filename(dest_handle, "main"));
    sqlite3_backup_finish(backup_handle);
    int status = sqlite3_close(dest_handle);
    assert(status == SQLITE_OK);
    ((void)status);
    if (unlink)
      remove(filename.c_str());
  }
}
Backup::~Backup() {
  if (alive)
    db->RemoveBackup(this);
  CloseHandles();
}
Backup::Backup(Database* db,
               sqlite3* dest_handle,
               sqlite3_backup* backup_handle,
               sqlite3_uint64 id,
               bool unlink)
    : node::ObjectWrap(),
      db(db),
      dest_handle(dest_handle),
      backup_handle(backup_handle),
      id(id),
      alive(true),
      unlink(unlink) {
  assert(db != NULL);
  assert(dest_handle != NULL);
  assert(backup_handle != NULL);
  db->AddBackup(this);
}
void Backup::JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Addon* addon = static_cast<Addon*>(info.Data().As<v8 ::External>()->Value());
  if (!addon->privileged_info)
    return ThrowTypeError("Disabled constructor");
  assert(info.IsConstructCall());
  Database* db =
      node ::ObjectWrap ::Unwrap<Database>(addon->privileged_info->This());
  if (!db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  if (db->GetState()->busy)
    return ThrowTypeError("This database connection is busy executing a query");

  v8::Local<v8::Object> database =
      (*addon->privileged_info)[0].As<v8::Object>();
  v8::Local<v8::String> attachedName =
      (*addon->privileged_info)[1].As<v8::String>();
  v8::Local<v8::String> destFile =
      (*addon->privileged_info)[2].As<v8::String>();
  bool unlink = (*addon->privileged_info)[3].As<v8::Boolean>()->Value();

  v8 ::Isolate* isolate = info.GetIsolate();
  sqlite3* dest_handle;
  v8::String::Utf8Value dest_file(isolate, destFile);
  v8::String::Utf8Value attached_name(isolate, attachedName);
  int mask = (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

  if (sqlite3_open_v2(*dest_file, &dest_handle, mask, NULL) != SQLITE_OK) {
    Database::ThrowSqliteError(addon, dest_handle);
    int status = sqlite3_close(dest_handle);
    assert(status == SQLITE_OK);
    ((void)status);
    return;
  }

  sqlite3_extended_result_codes(dest_handle, 1);
  sqlite3_limit(dest_handle, SQLITE_LIMIT_LENGTH, INT_MAX);
  sqlite3_backup* backup_handle =
      sqlite3_backup_init(dest_handle, "main", db->GetHandle(), *attached_name);
  if (backup_handle == NULL) {
    Database::ThrowSqliteError(addon, dest_handle);
    int status = sqlite3_close(dest_handle);
    assert(status == SQLITE_OK);
    ((void)status);
    return;
  }

  Backup* backup =
      new Backup(db, dest_handle, backup_handle, addon->NextId(), unlink);
  backup->Wrap(info.This());
  SetFrozen(isolate, isolate->GetCurrentContext(), info.This(),
            addon->cs.database, database);

  info.GetReturnValue().Set(info.This());
}
void Backup::JS_transfer(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Backup* backup = node ::ObjectWrap ::Unwrap<Backup>(info.This());
  if (info.Length() <= (0) || !info[0]->IsInt32())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a 32-bit signed integer");
  int pages = (info[0].As<v8 ::Int32>())->Value();
  if (!backup->db->GetState()->open)
    return ThrowTypeError("The database connection is not open");
  assert(backup->db->GetState()->busy == false);
  assert(backup->alive == true);

  sqlite3_backup* backup_handle = backup->backup_handle;
  int status = sqlite3_backup_step(backup_handle, pages) & 0xff;

  Addon* addon = backup->db->GetAddon();
  if (status == SQLITE_OK || status == SQLITE_DONE || status == SQLITE_BUSY) {
    int total_pages = sqlite3_backup_pagecount(backup_handle);
    int remaining_pages = sqlite3_backup_remaining(backup_handle);
    v8 ::Isolate* isolate = info.GetIsolate();
    v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
    v8::Local<v8::Object> result = v8::Object::New(isolate);
    result
        ->Set(ctx, addon->cs.totalPages.Get(isolate),
              v8::Int32::New(isolate, total_pages))
        .FromJust();
    result
        ->Set(ctx, addon->cs.remainingPages.Get(isolate),
              v8::Int32::New(isolate, remaining_pages))
        .FromJust();
    info.GetReturnValue().Set(result);
    if (status == SQLITE_DONE)
      backup->unlink = false;
  } else {
    Database::ThrowSqliteError(addon, sqlite3_errstr(status), status);
  }
}
void Backup::JS_close(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  Backup* backup = node ::ObjectWrap ::Unwrap<Backup>(info.This());
  assert(backup->db->GetState()->busy == false);
  if (backup->alive)
    backup->db->RemoveBackup(backup);
  backup->CloseHandles();
  info.GetReturnValue().Set(info.This());
}
Tokenizer::Tokenizer(v8::Isolate* isolate, v8::Local<v8::Function> run_fn)
    : isolate(isolate), run_fn(isolate, run_fn) {}
Tokenizer::~Tokenizer() {}
int Tokenizer::Run(void* pCtx,
                   char const* pText,
                   int nText,
                   int (*xToken)(void*, int, char const*, int, int, int)) {
  v8::HandleScope scope(isolate);
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  v8::Local<v8::Value> arg[] = {StringFromUtf8(isolate, pText, nText)};
  v8::Local<v8::Value> result = run_fn.Get(isolate)
                                    ->Call(ctx, v8::Undefined(isolate), 1, arg)
                                    .ToLocalChecked();
  if (!result->IsArray()) {
    ThrowTypeError("Expected array return value of tokenizer");
    return SQLITE_MISUSE;
  }
  v8::Local<v8::Array> indices = result.As<v8::Array>();
  int len = indices->Length();
  if (len % 3 != 0) {
    return SQLITE_MISUSE;
  }
  for (int i = 0; i < len; i += 3) {
    int64_t segment_start =
        indices->Get(ctx, i).ToLocalChecked()->IntegerValue(ctx).ToChecked();
    int64_t segment_end = indices->Get(ctx, i + 1)
                              .ToLocalChecked()
                              ->IntegerValue(ctx)
                              .ToChecked();
    v8::Local<v8::Value> maybe_normalized =
        indices->Get(ctx, i + 2).ToLocalChecked();
    if (segment_start < 0 || static_cast<int64_t>(segment_start) > nText) {
      return SQLITE_MISUSE;
    }
    if (segment_end < 0 || static_cast<int64_t>(segment_end) > nText) {
      return SQLITE_MISUSE;
    }
    if (segment_start > segment_end) {
      return SQLITE_MISUSE;
    }

    int rc;
    if (maybe_normalized->IsString()) {
      v8::String::Utf8Value normalized(
          isolate, indices->Get(ctx, i + 2).ToLocalChecked());
      rc = xToken(pCtx, 0, *normalized, normalized.length(), segment_start,
                  segment_end);
    } else {
      rc = xToken(pCtx, 0, &pText[segment_start], segment_end - segment_start,
                  segment_start, segment_end);
    }

    if (rc != SQLITE_OK) {
      return rc;
    }
  }
  return SQLITE_OK;
}
TokenizerModule::TokenizerModule(v8::Isolate* isolate,
                                 v8::Local<v8::Function> create_instance_fn)
    : isolate(isolate), create_instance_fn(isolate, create_instance_fn) {}
void TokenizerModule::xDestroy(void* pCtx) {
  TokenizerModule* m = static_cast<TokenizerModule*>(pCtx);
  delete m;
}
Tokenizer* TokenizerModule::CreateInstance(char const** azArg, int nArg) {
  v8::HandleScope scope(isolate);
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  v8::Local<v8::Array> params = v8::Array::New(isolate, nArg);
  for (int i = 0; i < nArg; i++) {
    params->Set(ctx, i, StringFromUtf8(isolate, azArg[i], -1)).ToChecked();
  }

  v8::Local<v8::Value> arg[] = {
      params,
  };
  v8::Local<v8::Function> run_fn =
      create_instance_fn.Get(isolate)
          ->Call(ctx, v8::Undefined(isolate), 1, arg)
          .ToLocalChecked()
          .As<v8::Function>();

  return new Tokenizer(isolate, run_fn);
}
int TokenizerModule::xCreate(void* pCtx,
                             char const** azArg,
                             int nArg,
                             Fts5Tokenizer** ppOut) {
  TokenizerModule* m = static_cast<TokenizerModule*>(pCtx);
  *ppOut = reinterpret_cast<Fts5Tokenizer*>(m->CreateInstance(azArg, nArg));
  return SQLITE_OK;
}
void TokenizerModule::xDelete(Fts5Tokenizer* tokenizer) {
  Tokenizer* t = reinterpret_cast<Tokenizer*>(tokenizer);
  delete t;
}
int TokenizerModule::xTokenize(
    Fts5Tokenizer* tokenizer,
    void* pCtx,
    int flags,
    char const* pText,
    int nText,
    int (*xToken)(void*, int, char const*, int, int, int)) {
  Tokenizer* t = reinterpret_cast<Tokenizer*>(tokenizer);

  return t->Run(pCtx, pText, nText, xToken);
}
fts5_tokenizer TokenizerModule::api_object = {
    &xCreate,
    &xDelete,
    &xTokenize,
};
SignalTokenizerModule::SignalTokenizerModule() {}
void SignalTokenizerModule::xDestroy(void* pCtx) {}
int SignalTokenizerModule::xCreate(void* pCtx,
                                   char const** azArg,
                                   int nArg,
                                   Fts5Tokenizer** ppOut) {
  TokenizerModule* m = static_cast<TokenizerModule*>(pCtx);
  *ppOut = reinterpret_cast<Fts5Tokenizer*>(m);
  return SQLITE_OK;
}
void SignalTokenizerModule::xDelete(Fts5Tokenizer* tokenizer) {}
fts5_tokenizer SignalTokenizerModule::api_object = {
    &xCreate,
    &xDelete,
    signal_fts5_tokenize,
};
void DataConverter::ThrowDataConversionError(sqlite3_context* invocation,
                                             bool isBigInt) {
  if (isBigInt) {
    ThrowRangeError(
        (GetDataErrorPrefix() + " a bigint that was too big").c_str());
  } else {
    ThrowTypeError((GetDataErrorPrefix() + " an invalid value").c_str());
  }
  PropagateJSError(invocation);
}
CustomFunction::CustomFunction(v8::Isolate* isolate,
                               Database* db,
                               char const* name,
                               v8::Local<v8::Function> fn,
                               bool safe_ints)
    : name(name),
      db(db),
      isolate(isolate),
      fn(isolate, fn),
      safe_ints(safe_ints) {}
CustomFunction::~CustomFunction() {}
void CustomFunction::xDestroy(void* self) {
  delete static_cast<CustomFunction*>(self);
}
void CustomFunction::xFunc(sqlite3_context* invocation,
                           int argc,
                           sqlite3_value** argv) {
  CustomFunction* self =
      static_cast<CustomFunction*>(sqlite3_user_data(invocation));
  v8 ::Isolate* isolate = self->isolate;
  v8 ::HandleScope scope(isolate);

  v8::Local<v8::Value> args_fast[4];
  v8::Local<v8::Value>* args = NULL;
  if (argc != 0) {
    args = argc <= 4 ? args_fast : ALLOC_ARRAY<v8::Local<v8::Value>>(argc);
    Data::GetArgumentsJS(isolate, args, argv, argc, self->safe_ints);
  }

  v8::MaybeLocal<v8::Value> maybeReturnValue = self->fn.Get(isolate)->Call(
      isolate->GetCurrentContext(), v8::Undefined(isolate), argc, args);
  if (args != args_fast)
    delete[] args;

  if (maybeReturnValue.IsEmpty())
    self->PropagateJSError(invocation);
  else
    Data::ResultValueFromJS(isolate, invocation,
                            maybeReturnValue.ToLocalChecked(), self);
}
void CustomFunction::PropagateJSError(sqlite3_context* invocation) {
  assert(db->GetState()->was_js_error == false);
  db->GetState()->was_js_error = true;
  sqlite3_result_error(invocation, "", 0);
}
std::string CustomFunction::GetDataErrorPrefix() {
  return std::string("User-defined function ") + name + "() returned";
}
CustomAggregate::CustomAggregate(v8::Isolate* isolate,
                                 Database* db,
                                 char const* name,
                                 v8::Local<v8::Value> start,
                                 v8::Local<v8::Function> step,
                                 v8::Local<v8::Value> inverse,
                                 v8::Local<v8::Value> result,
                                 bool safe_ints)
    : CustomFunction(isolate, db, name, step, safe_ints),
      invoke_result(result->IsFunction()),
      invoke_start(start->IsFunction()),
      inverse(isolate,
              inverse->IsFunction() ? inverse.As<v8::Function>()
                                    : v8::Local<v8::Function>()),
      result(isolate,
             result->IsFunction() ? result.As<v8::Function>()
                                  : v8::Local<v8::Function>()),
      start(isolate, start) {}
void CustomAggregate::xStep(sqlite3_context* invocation,
                            int argc,
                            sqlite3_value** argv) {
  xStepBase(invocation, argc, argv, &CustomAggregate::fn);
}
void CustomAggregate::xInverse(sqlite3_context* invocation,
                               int argc,
                               sqlite3_value** argv) {
  xStepBase(invocation, argc, argv, &CustomAggregate::inverse);
}
void CustomAggregate::xValue(sqlite3_context* invocation) {
  xValueBase(invocation, false);
}
void CustomAggregate::xFinal(sqlite3_context* invocation) {
  xValueBase(invocation, true);
}
CustomAggregate::Accumulator* CustomAggregate::GetAccumulator(
    sqlite3_context* invocation) {
  Accumulator* acc = static_cast<Accumulator*>(
      sqlite3_aggregate_context(invocation, sizeof(Accumulator)));
  if (!acc->initialized) {
    assert(acc->value.IsEmpty());
    acc->initialized = true;
    if (invoke_start) {
      v8::MaybeLocal<v8::Value> maybeSeed =
          start.Get(isolate).As<v8::Function>()->Call(
              isolate->GetCurrentContext(), v8::Undefined(isolate), 0, NULL);
      if (maybeSeed.IsEmpty())
        PropagateJSError(invocation);
      else
        acc->value.Reset(isolate, maybeSeed.ToLocalChecked());
    } else {
      assert(!start.IsEmpty());
      acc->value.Reset(isolate, start);
    }
  }
  return acc;
}
void CustomAggregate::DestroyAccumulator(sqlite3_context* invocation) {
  Accumulator* acc = static_cast<Accumulator*>(
      sqlite3_aggregate_context(invocation, sizeof(Accumulator)));
  assert(acc->initialized);
  acc->value.Reset();
}
void CustomAggregate::PropagateJSError(sqlite3_context* invocation) {
  DestroyAccumulator(invocation);
  CustomFunction::PropagateJSError(invocation);
}
CustomTable::CustomTable(v8::Isolate* isolate,
                         Database* db,
                         char const* name,
                         v8::Local<v8::Function> factory)
    : addon(db->GetAddon()),
      isolate(isolate),
      db(db),
      name(name),
      factory(isolate, factory) {}
void CustomTable::Destructor(void* self) {
  delete static_cast<CustomTable*>(self);
}
sqlite3_module CustomTable::MODULE = {
    0,      xCreate, xConnect, xBestIndex, xDisconnect, xDisconnect,
    xOpen,  xClose,  xFilter,  xNext,      xEof,        xColumn,
    xRowid, NULL,    NULL,     NULL,       NULL,        NULL,
    NULL,   NULL,    NULL,     NULL,       NULL,        NULL};
sqlite3_module CustomTable::EPONYMOUS_MODULE = {
    0,      NULL,   xConnect, xBestIndex, xDisconnect, xDisconnect,
    xOpen,  xClose, xFilter,  xNext,      xEof,        xColumn,
    xRowid, NULL,   NULL,     NULL,       NULL,        NULL,
    NULL,   NULL,   NULL,     NULL,       NULL,        NULL};
CustomTable::VTab::VTab(CustomTable* parent,
                        v8::Local<v8::Function> generator,
                        std::vector<std::string> parameter_names,
                        bool safe_ints)
    : parent(parent),
      parameter_count(parameter_names.size()),
      safe_ints(safe_ints),
      generator(parent->isolate, generator),
      parameter_names(parameter_names) {
  ((void)base);
}
CustomTable::TempDataConverter::TempDataConverter(CustomTable* parent)
    : parent(parent), status(SQLITE_OK) {}
void CustomTable::TempDataConverter::PropagateJSError(
    sqlite3_context* invocation) {
  status = SQLITE_ERROR;
  parent->PropagateJSError();
}
std::string CustomTable::TempDataConverter::GetDataErrorPrefix() {
  return std::string("Virtual table module \"") + parent->name + "\" yielded";
}
int CustomTable::xCreate(sqlite3* db_handle,
                         void* _self,
                         int argc,
                         char const* const* argv,
                         sqlite3_vtab** output,
                         char** errOutput) {
  return xConnect(db_handle, _self, argc, argv, output, errOutput);
}
int CustomTable::xConnect(sqlite3* db_handle,
                          void* _self,
                          int argc,
                          char const* const* argv,
                          sqlite3_vtab** output,
                          char** errOutput) {
  CustomTable* self = static_cast<CustomTable*>(_self);
  v8::Isolate* isolate = self->isolate;
  v8::HandleScope scope(isolate);
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  v8::Local<v8::Value>* args = ALLOC_ARRAY<v8::Local<v8::Value>>(argc);
  for (int i = 0; i < argc; ++i) {
    args[i] = StringFromUtf8(isolate, argv[i], -1);
  }

  v8::MaybeLocal<v8::Value> maybeReturnValue =
      self->factory.Get(isolate)->Call(ctx, v8::Undefined(isolate), argc, args);
  delete[] args;

  if (maybeReturnValue.IsEmpty()) {
    self->PropagateJSError();
    return SQLITE_ERROR;
  }

  v8::Local<v8::Array> returnValue =
      maybeReturnValue.ToLocalChecked().As<v8::Array>();
  v8::Local<v8::String> sqlString =
      returnValue->Get(ctx, 0).ToLocalChecked().As<v8::String>();
  v8::Local<v8::Function> generator =
      returnValue->Get(ctx, 1).ToLocalChecked().As<v8::Function>();
  v8::Local<v8::Array> parameterNames =
      returnValue->Get(ctx, 2).ToLocalChecked().As<v8::Array>();
  int safe_ints =
      returnValue->Get(ctx, 3).ToLocalChecked().As<v8::Int32>()->Value();
  bool direct_only =
      returnValue->Get(ctx, 4).ToLocalChecked().As<v8::Boolean>()->Value();

  v8::String::Utf8Value sql(isolate, sqlString);
  safe_ints = safe_ints < 2 ? safe_ints
                            : static_cast<int>(self->db->GetState()->safe_ints);

  std::vector<std::string> parameter_names;
  for (int i = 0, len = parameterNames->Length(); i < len; ++i) {
    v8::Local<v8::String> parameterName =
        parameterNames->Get(ctx, i).ToLocalChecked().As<v8::String>();
    v8::String::Utf8Value parameter_name(isolate, parameterName);
    parameter_names.emplace_back(*parameter_name);
  }

  if (sqlite3_declare_vtab(db_handle, *sql) != SQLITE_OK) {
    *errOutput =
        sqlite3_mprintf("failed to declare virtual table \"%s\"", argv[2]);
    return SQLITE_ERROR;
  }
  if (direct_only &&
      sqlite3_vtab_config(db_handle, SQLITE_VTAB_DIRECTONLY) != SQLITE_OK) {
    *errOutput =
        sqlite3_mprintf("failed to configure virtual table \"%s\"", argv[2]);
    return SQLITE_ERROR;
  }

  *output = (new VTab(self, generator, parameter_names, safe_ints))->Downcast();
  return SQLITE_OK;
}
int CustomTable::xDisconnect(sqlite3_vtab* vtab) {
  delete VTab::Upcast(vtab);
  return SQLITE_OK;
}
int CustomTable::xOpen(sqlite3_vtab* vtab, sqlite3_vtab_cursor** output) {
  *output = (new Cursor())->Downcast();
  return SQLITE_OK;
}
int CustomTable::xClose(sqlite3_vtab_cursor* cursor) {
  delete Cursor::Upcast(cursor);
  return SQLITE_OK;
}
int CustomTable::xFilter(sqlite3_vtab_cursor* _cursor,
                         int idxNum,
                         char const* idxStr,
                         int argc,
                         sqlite3_value** argv) {
  Cursor* cursor = Cursor::Upcast(_cursor);
  VTab* vtab = cursor->GetVTab();
  CustomTable* self = vtab->parent;
  Addon* addon = self->addon;
  v8::Isolate* isolate = self->isolate;
  v8::HandleScope scope(isolate);
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  v8::Local<v8::Value> args_fast[4];
  v8::Local<v8::Value>* args = NULL;
  int parameter_count = vtab->parameter_count;
  if (parameter_count != 0) {
    args = parameter_count <= 4
               ? args_fast
               : ALLOC_ARRAY<v8::Local<v8::Value>>(parameter_count);
    int argn = 0;
    bool safe_ints = vtab->safe_ints;
    for (int i = 0; i < parameter_count; ++i) {
      if (idxNum & 1 << i) {
        args[i] = Data::GetValueJS(isolate, argv[argn++], safe_ints);

        if (args[i]->IsNull()) {
          if (args != args_fast)
            delete[] args;
          cursor->done = true;
          return SQLITE_OK;
        }
      } else {
        args[i] = v8::Undefined(isolate);
      }
    }
  }

  v8::MaybeLocal<v8::Value> maybeIterator = vtab->generator.Get(isolate)->Call(
      ctx, v8::Undefined(isolate), parameter_count, args);
  if (args != args_fast)
    delete[] args;

  if (maybeIterator.IsEmpty()) {
    self->PropagateJSError();
    return SQLITE_ERROR;
  }

  v8::Local<v8::Object> iterator =
      maybeIterator.ToLocalChecked().As<v8::Object>();
  v8::Local<v8::Function> next = iterator->Get(ctx, addon->cs.next.Get(isolate))
                                     .ToLocalChecked()
                                     .As<v8::Function>();
  cursor->iterator.Reset(isolate, iterator);
  cursor->next.Reset(isolate, next);
  cursor->rowid = 0;

  return xNext(cursor->Downcast());
}
int CustomTable::xNext(sqlite3_vtab_cursor* _cursor) {
  Cursor* cursor = Cursor::Upcast(_cursor);
  CustomTable* self = cursor->GetVTab()->parent;
  Addon* addon = self->addon;
  v8::Isolate* isolate = self->isolate;
  v8::HandleScope scope(isolate);
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();

  v8::Local<v8::Object> iterator = cursor->iterator.Get(isolate);
  v8::Local<v8::Function> next = cursor->next.Get(isolate);

  v8::MaybeLocal<v8::Value> maybeRecord = next->Call(ctx, iterator, 0, NULL);
  if (maybeRecord.IsEmpty()) {
    self->PropagateJSError();
    return SQLITE_ERROR;
  }

  v8::Local<v8::Object> record = maybeRecord.ToLocalChecked().As<v8::Object>();
  bool done = record->Get(ctx, addon->cs.done.Get(isolate))
                  .ToLocalChecked()
                  .As<v8::Boolean>()
                  ->Value();
  if (!done) {
    cursor->row.Reset(isolate, record->Get(ctx, addon->cs.value.Get(isolate))
                                   .ToLocalChecked()
                                   .As<v8::Array>());
  }
  cursor->done = done;
  cursor->rowid += 1;

  return SQLITE_OK;
}
int CustomTable::xEof(sqlite3_vtab_cursor* cursor) {
  return Cursor::Upcast(cursor)->done;
}
int CustomTable::xColumn(sqlite3_vtab_cursor* _cursor,
                         sqlite3_context* invocation,
                         int column) {
  Cursor* cursor = Cursor::Upcast(_cursor);
  CustomTable* self = cursor->GetVTab()->parent;
  TempDataConverter temp_data_converter(self);
  v8::Isolate* isolate = self->isolate;
  v8::HandleScope scope(isolate);

  v8::Local<v8::Array> row = cursor->row.Get(isolate);
  v8::MaybeLocal<v8::Value> maybeColumnValue =
      row->Get(isolate->GetCurrentContext(), column);
  if (maybeColumnValue.IsEmpty()) {
    temp_data_converter.PropagateJSError(NULL);
  } else {
    Data::ResultValueFromJS(isolate, invocation,
                            maybeColumnValue.ToLocalChecked(),
                            &temp_data_converter);
  }
  return temp_data_converter.status;
}
int CustomTable::xRowid(sqlite3_vtab_cursor* cursor, sqlite_int64* output) {
  *output = Cursor::Upcast(cursor)->rowid;
  return SQLITE_OK;
}
int CustomTable::xBestIndex(sqlite3_vtab* vtab, sqlite3_index_info* output) {
  int parameter_count = VTab::Upcast(vtab)->parameter_count;
  int argument_count = 0;
  std::vector<std::pair<int, int>> forwarded;

  for (int i = 0, len = output->nConstraint; i < len; ++i) {
    auto item = output->aConstraint[i];

    if (item.op == SQLITE_INDEX_CONSTRAINT_LIMIT ||
        item.op == SQLITE_INDEX_CONSTRAINT_OFFSET) {
      continue;
    }

    if (item.iColumn >= 0 && item.iColumn < parameter_count) {
      if (item.op != SQLITE_INDEX_CONSTRAINT_EQ) {
        sqlite3_free(vtab->zErrMsg);
        vtab->zErrMsg = sqlite3_mprintf(
            "virtual table parameter \"%s\" can only be constrained by the '=' "
            "operator",
            VTab::Upcast(vtab)->parameter_names.at(item.iColumn).c_str());
        return SQLITE_ERROR;
      }
      if (!item.usable) {
        return SQLITE_CONSTRAINT;
      }
      forwarded.emplace_back(item.iColumn, i);
    }
  }

  std::sort(forwarded.begin(), forwarded.end());
  for (std::pair<int, int> pair : forwarded) {
    int bit = 1 << pair.first;
    if (!(output->idxNum & bit)) {
      output->idxNum |= bit;
      output->aConstraintUsage[pair.second].argvIndex = ++argument_count;
      output->aConstraintUsage[pair.second].omit = 1;
    }
  }

  output->estimatedCost = output->estimatedRows =
      1000000000 / (argument_count + 1);
  return SQLITE_OK;
}
void CustomTable::PropagateJSError() {
  assert(db->GetState()->was_js_error == false);
  db->GetState()->was_js_error = true;
}
namespace Data {
v8::Local<v8::Value> GetValueJS(v8::Isolate* isolate,
                                sqlite3_stmt* handle,
                                int column,
                                bool safe_ints) {
  switch (sqlite3_column_type(handle, column)) {
    case SQLITE_INTEGER:
      if (safe_ints) {
        return v8 ::BigInt ::New(isolate, sqlite3_column_int64(handle, column));
      }
    case SQLITE_FLOAT:
      return v8 ::Number ::New(isolate, sqlite3_column_double(handle, column));
    case SQLITE_TEXT:
      return StringFromUtf8(
          isolate,
          reinterpret_cast<const char*>(sqlite3_column_text(handle, column)),
          sqlite3_column_bytes(handle, column));
    case SQLITE_BLOB:
      return node ::Buffer ::Copy(
                 isolate,
                 static_cast<const char*>(sqlite3_column_blob(handle, column)),
                 sqlite3_column_bytes(handle, column))
          .ToLocalChecked();
    default:
      assert(sqlite3_column_type(handle, column) == SQLITE_NULL);
      return v8 ::Null(isolate);
  }
  assert(false);
  ;
}
v8::Local<v8::Value> GetValueJS(v8::Isolate* isolate,
                                sqlite3_value* value,
                                bool safe_ints) {
  switch (sqlite3_value_type(value)) {
    case SQLITE_INTEGER:
      if (safe_ints) {
        return v8 ::BigInt ::New(isolate, sqlite3_value_int64(value));
      }
    case SQLITE_FLOAT:
      return v8 ::Number ::New(isolate, sqlite3_value_double(value));
    case SQLITE_TEXT:
      return StringFromUtf8(
          isolate, reinterpret_cast<const char*>(sqlite3_value_text(value)),
          sqlite3_value_bytes(value));
    case SQLITE_BLOB:
      return node ::Buffer ::Copy(
                 isolate, static_cast<const char*>(sqlite3_value_blob(value)),
                 sqlite3_value_bytes(value))
          .ToLocalChecked();
    default:
      assert(sqlite3_value_type(value) == SQLITE_NULL);
      return v8 ::Null(isolate);
  }
  assert(false);
  ;
}
#ifdef V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetFlatRowJS(v8::Isolate* isolate,
                                  v8::Local<v8::Context> ctx,
                                  sqlite3_stmt* handle,
                                  bool safe_ints,
                                  v8::LocalVector<v8::Name>& keys) {
  if (keys.size() == 0) {
    int column_count = sqlite3_column_count(handle);
    keys.reserve(column_count);
    for (int i = 0; i < column_count; ++i) {
      keys.emplace_back(
          InternalizedFromUtf8(isolate, sqlite3_column_name(handle, i), -1));
    }
  }

  v8::LocalVector<v8::Value> values(isolate);
  values.reserve(keys.size());

  for (size_t i = 0; i < keys.size(); ++i) {
    values.emplace_back(Data::GetValueJS(isolate, handle, i, safe_ints));
  }

  return v8::Object::New(isolate, v8::Null(isolate), keys.data(), values.data(),
                         keys.size());
}
#else  // !V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetFlatRowJS(v8::Isolate* isolate,
                                  v8::Local<v8::Context> ctx,
                                  sqlite3_stmt* handle,
                                  bool safe_ints) {
  v8::Local<v8::Object> row = v8::Object::New(isolate);
  int column_count = sqlite3_column_count(handle);
  for (int i = 0; i < column_count; ++i) {
    row->Set(ctx,
             InternalizedFromUtf8(isolate, sqlite3_column_name(handle, i), -1),
             Data::GetValueJS(isolate, handle, i, safe_ints))
        .FromJust();
  }
  return row;
}
#endif
v8::Local<v8::Value> GetExpandedRowJS(v8::Isolate* isolate,
                                      v8::Local<v8::Context> ctx,
                                      sqlite3_stmt* handle,
                                      bool safe_ints) {
  v8::Local<v8::Object> row = v8::Object::New(isolate);
  int column_count = sqlite3_column_count(handle);
  for (int i = 0; i < column_count; ++i) {
    const char* table_raw = sqlite3_column_table_name(handle, i);
    v8::Local<v8::String> table =
        InternalizedFromUtf8(isolate, table_raw == NULL ? "$" : table_raw, -1);
    v8::Local<v8::String> column =
        InternalizedFromUtf8(isolate, sqlite3_column_name(handle, i), -1);
    v8::Local<v8::Value> value =
        Data::GetValueJS(isolate, handle, i, safe_ints);
    if (row->HasOwnProperty(ctx, table).FromJust()) {
      row->Get(ctx, table)
          .ToLocalChecked()
          .As<v8::Object>()
          ->Set(ctx, column, value)
          .FromJust();
    } else {
      v8::Local<v8::Object> nested = v8::Object::New(isolate);
      row->Set(ctx, table, nested).FromJust();
      nested->Set(ctx, column, value).FromJust();
    }
  }
  return row;
}
v8::Local<v8::Value> GetRawRowJS(v8::Isolate* isolate,
                                 v8::Local<v8::Context> ctx,
                                 sqlite3_stmt* handle,
                                 bool safe_ints) {
  v8::Local<v8::Array> row = v8::Array::New(isolate);
  int column_count = sqlite3_column_count(handle);
  for (int i = 0; i < column_count; ++i) {
    row->Set(ctx, i, Data::GetValueJS(isolate, handle, i, safe_ints))
        .FromJust();
  }
  return row;
}
#ifdef V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetRowJS(v8::Isolate* isolate,
                              v8::Local<v8::Context> ctx,
                              sqlite3_stmt* handle,
                              bool safe_ints,
                              char mode,
                              v8::LocalVector<v8::Name>& keys) {
  if (mode == FLAT)
    return GetFlatRowJS(isolate, ctx, handle, safe_ints, keys);
#else  // !V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetRowJS(v8::Isolate* isolate,
                              v8::Local<v8::Context> ctx,
                              sqlite3_stmt* handle,
                              bool safe_ints,
                              char mode) {
  if (mode == FLAT)
    return GetFlatRowJS(isolate, ctx, handle, safe_ints);
#endif
  if (mode == PLUCK)
    return GetValueJS(isolate, handle, 0, safe_ints);
  if (mode == EXPAND)
    return GetExpandedRowJS(isolate, ctx, handle, safe_ints);
  if (mode == RAW)
    return GetRawRowJS(isolate, ctx, handle, safe_ints);
  assert(false);
  return v8::Local<v8::Value>();
}
void GetArgumentsJS(v8::Isolate* isolate,
                    v8::Local<v8::Value>* out,
                    sqlite3_value** values,
                    int argument_count,
                    bool safe_ints) {
  assert(argument_count > 0);
  for (int i = 0; i < argument_count; ++i) {
    out[i] = Data::GetValueJS(isolate, values[i], safe_ints);
  }
}
int BindValueFromJS(v8::Isolate* isolate,
                    sqlite3_stmt* handle,
                    int index,
                    v8::Local<v8::Value> value) {
  if (value->IsNumber()) {
    return sqlite3_bind_double(handle, index, value.As<v8 ::Number>()->Value());
  } else if (value->IsBigInt()) {
    bool lossless;
    int64_t v = value.As<v8 ::BigInt>()->Int64Value(&lossless);
    if (lossless) {
      return sqlite3_bind_int64(handle, index, v);
    }
  } else if (value->IsString()) {
    v8 ::String ::Utf8Value utf8(isolate, value.As<v8 ::String>());
    return sqlite3_bind_text(handle, index, *utf8, utf8.length(),
                             SQLITE_TRANSIENT);
  } else if (node ::Buffer ::HasInstance(value)) {
    const char* data = node ::Buffer ::Data(value);
    return sqlite3_bind_blob(handle, index, data ? data : "",
                             node ::Buffer ::Length(value), SQLITE_TRANSIENT);
  } else if (value->IsNull() || value->IsUndefined()) {
    return sqlite3_bind_null(handle, index);
  };
  return value->IsBigInt() ? SQLITE_TOOBIG : -1;
}
void ResultValueFromJS(v8::Isolate* isolate,
                       sqlite3_context* invocation,
                       v8::Local<v8::Value> value,
                       DataConverter* converter) {
  if (value->IsNumber()) {
    return sqlite3_result_double(invocation, value.As<v8 ::Number>()->Value());
  } else if (value->IsBigInt()) {
    bool lossless;
    int64_t v = value.As<v8 ::BigInt>()->Int64Value(&lossless);
    if (lossless) {
      return sqlite3_result_int64(invocation, v);
    }
  } else if (value->IsString()) {
    v8 ::String ::Utf8Value utf8(isolate, value.As<v8 ::String>());
    return sqlite3_result_text(invocation, *utf8, utf8.length(),
                               SQLITE_TRANSIENT);
  } else if (node ::Buffer ::HasInstance(value)) {
    const char* data = node ::Buffer ::Data(value);
    return sqlite3_result_blob(invocation, data ? data : "",
                               node ::Buffer ::Length(value), SQLITE_TRANSIENT);
  } else if (value->IsNull() || value->IsUndefined()) {
    return sqlite3_result_null(invocation);
  };
  converter->ThrowDataConversionError(invocation, value->IsBigInt());
}
}  // namespace Data
Binder::Binder(sqlite3_stmt* _handle) {
  handle = _handle;
  param_count = sqlite3_bind_parameter_count(_handle);
  anon_index = 0;
  success = true;
}
bool Binder::Bind(v8::FunctionCallbackInfo<v8 ::Value> const& info,
                  int argc,
                  Statement* stmt) {
  assert(anon_index == 0);
  Result result = BindArgs(info, argc, stmt);
  if (success && result.count != param_count) {
    if (result.count < param_count) {
      if (!result.bound_object &&
          stmt->GetBindMap(info.GetIsolate())->GetSize()) {
        Fail(ThrowTypeError, "Missing named parameters");
      } else {
        Fail(ThrowRangeError, "Too few parameter values were provided");
      }
    } else {
      Fail(ThrowRangeError, "Too many parameter values were provided");
    }
  }
  return success;
}
void Binder::Fail(void (*Throw)(char const*), char const* message) {
  assert(success == true);
  assert((Throw == NULL) == (message == NULL));
  assert(Throw == ThrowError || Throw == ThrowTypeError ||
         Throw == ThrowRangeError || Throw == NULL);
  if (Throw)
    Throw(message);
  success = false;
}
int Binder::NextAnonIndex() {
  while (sqlite3_bind_parameter_name(handle, ++anon_index) != NULL) {
  }
  return anon_index;
}
void Binder::BindValue(v8::Isolate* isolate,
                       v8::Local<v8::Value> value,
                       int index) {
  int status = Data::BindValueFromJS(isolate, handle, index, value);
  if (status != SQLITE_OK) {
    switch (status) {
      case -1:
        return Fail(ThrowTypeError,
                    "SQLite3 can only bind numbers, strings, bigints, buffers, "
                    "and null");
      case SQLITE_TOOBIG:
        return Fail(ThrowRangeError,
                    "The bound string, buffer, or bigint is too big");
      case SQLITE_RANGE:
        return Fail(ThrowRangeError, "Too many parameter values were provided");
      case SQLITE_NOMEM:
        return Fail(ThrowError, "Out of memory");
      default:
        return Fail(
            ThrowError,
            "An unexpected error occured while trying to bind parameters");
    }
    assert(false);
  }
}
int Binder::BindArray(v8::Isolate* isolate, v8::Local<v8::Array> arr) {
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
  uint32_t length = arr->Length();
  if (length > INT_MAX) {
    Fail(ThrowRangeError, "Too many parameter values were provided");
    return 0;
  }
  int len = static_cast<int>(length);
  for (int i = 0; i < len; ++i) {
    v8::MaybeLocal<v8::Value> maybeValue = arr->Get(ctx, i);
    if (maybeValue.IsEmpty()) {
      Fail(NULL, NULL);
      return i;
    }
    BindValue(isolate, maybeValue.ToLocalChecked(), NextAnonIndex());
    if (!success) {
      return i;
    }
  }
  return len;
}
int Binder::BindObject(v8::Isolate* isolate,
                       v8::Local<v8::Object> obj,
                       Statement* stmt) {
  v8 ::Local<v8 ::Context> ctx = isolate->GetCurrentContext();
  BindMap* bind_map = stmt->GetBindMap(isolate);
  BindMap::Pair* pairs = bind_map->GetPairs();
  int len = bind_map->GetSize();

  for (int i = 0; i < len; ++i) {
    v8::Local<v8::String> key = pairs[i].GetName(isolate);

    v8::Maybe<bool> has_property = obj->HasOwnProperty(ctx, key);
    if (has_property.IsNothing()) {
      Fail(NULL, NULL);
      return i;
    }
    if (!has_property.FromJust()) {
      v8::String::Utf8Value param_name(isolate, key);
      Fail(ThrowRangeError,
           (std::string("Missing named parameter \"") + *param_name + "\"")
               .c_str());
      return i;
    }

    v8::MaybeLocal<v8::Value> maybeValue = obj->Get(ctx, key);
    if (maybeValue.IsEmpty()) {
      Fail(NULL, NULL);
      return i;
    }

    BindValue(isolate, maybeValue.ToLocalChecked(), pairs[i].GetIndex());
    if (!success) {
      return i;
    }
  }

  return len;
}
Binder::Result Binder::BindArgs(
    v8::FunctionCallbackInfo<v8 ::Value> const& info,
    int argc,
    Statement* stmt) {
  v8 ::Isolate* isolate = info.GetIsolate();
  int count = 0;
  bool bound_object = false;

  for (int i = 0; i < argc; ++i) {
    v8::Local<v8::Value> arg = info[i];

    if (arg->IsArray()) {
      count += BindArray(isolate, arg.As<v8::Array>());
      if (!success)
        break;
      continue;
    }

    if (arg->IsObject() && !node::Buffer::HasInstance(arg)) {
      v8::Local<v8::Object> obj = arg.As<v8::Object>();
      if (IsPlainObject(isolate, obj)) {
        if (bound_object) {
          Fail(ThrowTypeError,
               "You cannot specify named parameters in two different objects");
          break;
        }
        bound_object = true;

        count += BindObject(isolate, obj, stmt);
        if (!success)
          break;
        continue;
      } else if (stmt->GetBindMap(isolate)->GetSize()) {
        Fail(ThrowTypeError,
             "Named parameters can only be passed within plain objects");
        break;
      }
    }

    BindValue(isolate, arg, NextAnonIndex());
    if (!success)
      break;
    count += 1;
  }

  return {count, bound_object};
}
void Addon::JS_setErrorConstructor(
    v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  if (info.Length() <= (0) || !info[0]->IsFunction())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a function");
  v8 ::Local<v8 ::Function> SqliteError = (info[0].As<v8 ::Function>());
  static_cast<Addon*>(info.Data().As<v8 ::External>()->Value())
      ->SqliteError.Reset(info.GetIsolate(), SqliteError);
}
void Addon::JS_setLogHandler(v8::FunctionCallbackInfo<v8 ::Value> const& info) {
  if (info.Length() <= (0) || !info[0]->IsFunction())
    return ThrowTypeError(
        "Expected "
        "first"
        " argument to be "
        "a function");
  v8 ::Local<v8 ::Function> LogHandler = (info[0].As<v8 ::Function>());
  static_cast<Addon*>(info.Data().As<v8 ::External>()->Value())
      ->LogHandler.Reset(info.GetIsolate(), LogHandler);
}
void Addon::Cleanup(void* ptr) {
  Addon* addon = static_cast<Addon*>(ptr);
  for (Database* db : addon->dbs)
    db->CloseHandles();
  addon->dbs.clear();
  delete addon;
}
void Addon::SqliteLog(void* pArg, int iErrCode, char const* zMsg) {
  Addon* addon = static_cast<Addon*>(uv_key_get(&thread_key));
  if (addon->LogHandler.IsEmpty()) {
    return;
  }
  v8 ::Isolate* isolate = v8 ::Isolate ::GetCurrent();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Function> handler = addon->LogHandler.Get(isolate);
  v8::Local<v8::Value> arg[] = {
      v8::Integer::New(isolate, static_cast<int32_t>(iErrCode)),
      StringFromUtf8(isolate, zMsg, -1)};
  handler->Call(isolate->GetCurrentContext(), v8::Undefined(isolate), 2, arg)
      .ToLocalChecked();
}
void Addon::InitLoggerOnce() {
  int err = uv_key_create(&thread_key);
  if (err != 0) {
    abort();
  }
  sqlite3_initialize();
  sqlite3_config(SQLITE_CONFIG_LOG, Addon::SqliteLog, nullptr);
}
Addon::Addon(v8::Isolate* isolate)
    : privileged_info(NULL), next_id(0), cs(isolate) {
  static uv_once_t init_once = UV_ONCE_INIT;
  uv_once(&init_once, InitLoggerOnce);
  uv_key_set(&thread_key, this);
}
uv_key_t Addon::thread_key;
#undef LZZ_INLINE
