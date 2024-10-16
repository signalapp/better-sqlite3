// better_sqlite3.hpp
//

#ifndef LZZ_BETTER_SQLITE3_better_sqlite3_hpp
#define LZZ_BETTER_SQLITE3_better_sqlite3_hpp
#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>
#include <sqlite3.h>
#include <uv.h>
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include "signal-tokenizer.h"

// See: https://github.com/v8/v8/commit/e1649301dfbfd34a448c3a0232c8a6206b716c73
// Required V8 verison: 12.0.54 or higher

#if V8_MAJOR_VERSION > 12 ||     \
    V8_MINOR_VERSION == 12 &&    \
        (V8_MINOR_VERSION > 0 || \
         V8_MINOR_VERSION == 0 && V8_PATCH_VERSION >= 54)
#define V8_HAS_LOCAL_VECTOR
#endif

template <class T>
using CopyablePersistent = v8::Global<T>;

static bool IsPlainObject(v8::Isolate* isolate, v8::Local<v8::Object> obj);

#define LZZ_INLINE inline
v8::Local<v8::String> StringFromUtf8(v8::Isolate* isolate,
                                     char const* data,
                                     int length);
v8::Local<v8::String> InternalizedFromUtf8(v8::Isolate* isolate,
                                           char const* data,
                                           int length);
v8::Local<v8::Value> InternalizedFromUtf8OrNull(v8::Isolate* isolate,
                                                char const* data,
                                                int length);
v8::Local<v8::String> InternalizedFromLatin1(v8::Isolate* isolate,
                                             char const* str);
void SetFrozen(v8::Isolate* isolate,
               v8::Local<v8::Context> ctx,
               v8::Local<v8::Object> obj,
               CopyablePersistent<v8::String>& key,
               v8::Local<v8::Value> value);
void ThrowError(char const* message);
void ThrowTypeError(char const* message);
void ThrowRangeError(char const* message);
bool IS_SKIPPED(char c);
template <typename T>
T* ALLOC_ARRAY(size_t count);
template <typename T>
void FREE_ARRAY(T* array_pointer);
v8::Local<v8::FunctionTemplate> NewConstructorTemplate(
    v8::Isolate* isolate,
    v8::Local<v8::External> data,
    v8::FunctionCallback func,
    char const* name);
void SetPrototypeMethod(v8::Isolate* isolate,
                        v8::Local<v8::External> data,
                        v8::Local<v8::FunctionTemplate> recv,
                        char const* name,
                        v8::FunctionCallback func);
void SetPrototypeSymbolMethod(v8::Isolate* isolate,
                              v8::Local<v8::External> data,
                              v8::Local<v8::FunctionTemplate> recv,
                              v8::Local<v8::Symbol> symbol,
                              v8::FunctionCallback func);
void SetPrototypeGetter(v8::Isolate* isolate,
                        v8::Local<v8::External> data,
                        v8::Local<v8::FunctionTemplate> recv,
                        char const* name,
                        v8::FunctionCallback func);
class CS {
 public:
  v8::Local<v8::String> Code(v8::Isolate* isolate, int code);
  explicit CS(v8::Isolate* isolate);
  CopyablePersistent<v8::String> database;
  CopyablePersistent<v8::String> reader;
  CopyablePersistent<v8::String> source;
  CopyablePersistent<v8::String> memory;
  CopyablePersistent<v8::String> readonly;
  CopyablePersistent<v8::String> name;
  CopyablePersistent<v8::String> next;
  CopyablePersistent<v8::String> length;
  CopyablePersistent<v8::String> done;
  CopyablePersistent<v8::String> value;
  CopyablePersistent<v8::String> changes;
  CopyablePersistent<v8::String> lastInsertRowid;
  CopyablePersistent<v8::String> statement;
  CopyablePersistent<v8::String> column;
  CopyablePersistent<v8::String> table;
  CopyablePersistent<v8::String> type;
  CopyablePersistent<v8::String> totalPages;
  CopyablePersistent<v8::String> remainingPages;

 private:
  static void SetString(v8::Isolate* isolate,
                        CopyablePersistent<v8::String>& constant,
                        char const* str);
  void SetCode(v8::Isolate* isolate, int code, char const* str);
  std::unordered_map<int, CopyablePersistent<v8::String>> codes;
};
class BindMap {
 public:
  class Pair {
    friend class BindMap;

   public:
    int GetIndex();
    v8::Local<v8::String> GetName(v8::Isolate* isolate);

   private:
    explicit Pair(v8::Isolate* isolate, char const* name, int index);
    explicit Pair(v8::Isolate* isolate, Pair* pair);
    CopyablePersistent<v8::String> const name;
    int const index;
  };
  explicit BindMap(char _);
  ~BindMap();
  Pair* GetPairs();
  int GetSize();
  void Add(v8::Isolate* isolate, char const* name, int index);

 private:
  void Grow(v8::Isolate* isolate);
  Pair* pairs;
  int capacity;
  int length;
};
struct Addon;
class Statement;
class TokenizerModule;
class SignalTokenizerModule;
class Backup;
class Database : public node::ObjectWrap {
 public:
  static v8::Local<v8 ::Function> Init(v8::Isolate* isolate,
                                       v8::Local<v8 ::External> data);
  class CompareDatabase {
   public:
    bool operator()(Database const* const a, Database const* const b) const;
  };
  class CompareStatement {
   public:
    bool operator()(Statement const* const a, Statement const* const b) const;
  };
  class CompareBackup {
   public:
    bool operator()(Backup const* const a, Backup const* const b) const;
  };
  void ThrowDatabaseError();
  static void ThrowSqliteError(Addon* addon, sqlite3* db_handle);
  static void ThrowSqliteError(Addon* addon, char const* message, int code);
  bool Log(v8::Isolate* isolate, sqlite3_stmt* handle);
  void AddStatement(Statement* stmt);
  void RemoveStatement(Statement* stmt);
  void AddBackup(Backup* backup);
  void RemoveBackup(Backup* backup);
  struct State {
    bool const open;
    bool busy;
    bool const safe_ints;
    bool const unsafe_mode;
    bool was_js_error;
    bool const has_logger;
    unsigned short int iterators;
    Addon* const addon;
  };
  State* GetState();
  sqlite3* GetHandle();
  Addon* GetAddon();
  void CloseHandles();
  ~Database();

 private:
  explicit Database(v8::Isolate* isolate,
                    Addon* addon,
                    sqlite3* db_handle,
                    v8::Local<v8::Value> logger);
  fts5_api* GetFTS5API();
  static void JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_prepare(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_exec(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_backup(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_function(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_aggregate(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_table(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_close(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_defaultSafeIntegers(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_unsafeMode(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_createFTS5Tokenizer(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static int SignalTokenizeCallback(void* tokensPtr,
                                    int _flags,
                                    char const* token,
                                    int len,
                                    int _start,
                                    int _end);
  static void JS_signalTokenize(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_open(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_inTransaction(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static bool Deserialize(v8::Local<v8::Object> buffer,
                          Addon* addon,
                          sqlite3* db_handle,
                          bool readonly);
  static void FreeSerialization(char* data, void* _);
  static int const MAX_BUFFER_SIZE =
      node::Buffer::kMaxLength > INT_MAX
          ? INT_MAX
          : static_cast<int>(node::Buffer::kMaxLength);
  static int const MAX_STRING_SIZE =
      v8::String::kMaxLength > INT_MAX
          ? INT_MAX
          : static_cast<int>(v8::String::kMaxLength);
  sqlite3* const db_handle;
  bool open;
  bool busy;
  bool safe_ints;
  bool unsafe_mode;
  bool was_js_error;
  bool const has_logger;
  unsigned short int iterators;
  Addon* const addon;
  CopyablePersistent<v8::Value> const logger;
  std::set<Statement*, CompareStatement> stmts;
  std::set<Backup*, CompareBackup> backups;
};
class Statement : public node::ObjectWrap {
  friend class StatementIterator;

 public:
  static v8::Local<v8 ::Function> Init(v8::Isolate* isolate,
                                       v8::Local<v8 ::External> data);
  static bool Compare(Statement const* const a, Statement const* const b);
  BindMap* GetBindMap(v8::Isolate* isolate);
  void CloseHandles();
  ~Statement();

 private:
  class Extras {
    friend class Statement;
    explicit Extras(sqlite3_uint64 id);
    BindMap bind_map;
    sqlite3_uint64 const id;
  };
  explicit Statement(Database* db,
                     sqlite3_stmt* handle,
                     sqlite3_uint64 id,
                     bool returns_data);
  static void JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_run(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_get(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_all(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_iterate(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_bind(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_pluck(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_expand(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_raw(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_safeIntegers(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_columns(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_busy(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  Database* const db;
  sqlite3_stmt* const handle;
  Extras* const extras;
  bool alive;
  bool locked;
  bool bound;
  bool has_bind_map;
  bool safe_ints;
  char mode;
  bool const returns_data;
};
class StatementIterator : public node::ObjectWrap {
 public:
  static v8::Local<v8 ::Function> Init(v8::Isolate* isolate,
                                       v8::Local<v8 ::External> data);
  ~StatementIterator();

 private:
  explicit StatementIterator(Statement* stmt, bool bound);
  static void JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_next(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_return(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_symbolIterator(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  void Next(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  void Return(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  void Throw();
  void Cleanup();
  static v8::Local<v8::Object> NewRecord(v8::Isolate* isolate,
                                         v8::Local<v8::Context> ctx,
                                         v8::Local<v8::Value> value,
                                         Addon* addon,
                                         bool done);
  static v8::Local<v8::Object> DoneRecord(v8::Isolate* isolate, Addon* addon);
  Statement* const stmt;
  sqlite3_stmt* const handle;
  Database::State* const db_state;
  bool const bound;
  bool const safe_ints;
  char const mode;
  bool alive;
  bool logged;
};
class Backup : public node::ObjectWrap {
 public:
  static v8::Local<v8 ::Function> Init(v8::Isolate* isolate,
                                       v8::Local<v8 ::External> data);
  static bool Compare(Backup const* const a, Backup const* const b);
  void CloseHandles();
  ~Backup();

 private:
  explicit Backup(Database* db,
                  sqlite3* dest_handle,
                  sqlite3_backup* backup_handle,
                  sqlite3_uint64 id,
                  bool unlink);
  static void JS_new(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_transfer(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_close(v8::FunctionCallbackInfo<v8 ::Value> const& info);
  Database* const db;
  sqlite3* const dest_handle;
  sqlite3_backup* const backup_handle;
  sqlite3_uint64 const id;
  bool alive;
  bool unlink;
};
class Tokenizer {
 public:
  Tokenizer(v8::Isolate* isolate, v8::Local<v8::Function> run_fn);
  ~Tokenizer();
  int Run(void* pCtx,
          char const* pText,
          int nText,
          int (*xToken)(void*, int, char const*, int, int, int));

 private:
  v8::Isolate* isolate;
  CopyablePersistent<v8::Function> const run_fn;
};
class TokenizerModule {
 public:
  TokenizerModule(v8::Isolate* isolate,
                  v8::Local<v8::Function> create_instance_fn);
  static void xDestroy(void* pCtx);
  fts5_tokenizer* get_api_object();

 private:
  Tokenizer* CreateInstance(char const** azArg, int nArg);
  static int xCreate(void* pCtx,
                     char const** azArg,
                     int nArg,
                     Fts5Tokenizer** ppOut);
  static void xDelete(Fts5Tokenizer* tokenizer);
  static int xTokenize(Fts5Tokenizer* tokenizer,
                       void* pCtx,
                       int flags,
                       char const* pText,
                       int nText,
                       int (*xToken)(void*, int, char const*, int, int, int));
  static fts5_tokenizer api_object;
  v8::Isolate* isolate;
  CopyablePersistent<v8::Function> const create_instance_fn;
};
class SignalTokenizerModule {
 public:
  SignalTokenizerModule();
  static void xDestroy(void* pCtx);
  fts5_tokenizer* get_api_object();

 private:
  static int xCreate(void* pCtx,
                     char const** azArg,
                     int nArg,
                     Fts5Tokenizer** ppOut);
  static void xDelete(Fts5Tokenizer* tokenizer);
  static fts5_tokenizer api_object;
};
class DataConverter {
 public:
  void ThrowDataConversionError(sqlite3_context* invocation, bool isBigInt);

 protected:
  virtual void PropagateJSError(sqlite3_context* invocation) = 0;
  virtual std::string GetDataErrorPrefix() = 0;
};
class CustomFunction : protected DataConverter {
 public:
  explicit CustomFunction(v8::Isolate* isolate,
                          Database* db,
                          char const* name,
                          v8::Local<v8::Function> fn,
                          bool safe_ints);
  virtual ~CustomFunction();
  static void xDestroy(void* self);
  static void xFunc(sqlite3_context* invocation,
                    int argc,
                    sqlite3_value** argv);

 protected:
  void PropagateJSError(sqlite3_context* invocation);
  std::string GetDataErrorPrefix();

 private:
  std::string const name;
  Database* const db;

 protected:
  v8::Isolate* const isolate;
  CopyablePersistent<v8::Function> const fn;
  bool const safe_ints;
};
class CustomAggregate : public CustomFunction {
 public:
  explicit CustomAggregate(v8::Isolate* isolate,
                           Database* db,
                           char const* name,
                           v8::Local<v8::Value> start,
                           v8::Local<v8::Function> step,
                           v8::Local<v8::Value> inverse,
                           v8::Local<v8::Value> result,
                           bool safe_ints);
  static void xStep(sqlite3_context* invocation,
                    int argc,
                    sqlite3_value** argv);
  static void xInverse(sqlite3_context* invocation,
                       int argc,
                       sqlite3_value** argv);
  static void xValue(sqlite3_context* invocation);
  static void xFinal(sqlite3_context* invocation);

 private:
  static void xStepBase(
      sqlite3_context* invocation,
      int argc,
      sqlite3_value** argv,
      CopyablePersistent<v8::Function> const CustomAggregate::*ptrtm);
  static void xValueBase(sqlite3_context* invocation, bool is_final);
  struct Accumulator {
   public:
    CopyablePersistent<v8::Value> value;
    bool initialized;
    bool is_window;
  };
  Accumulator* GetAccumulator(sqlite3_context* invocation);
  static void DestroyAccumulator(sqlite3_context* invocation);
  void PropagateJSError(sqlite3_context* invocation);
  bool const invoke_result;
  bool const invoke_start;
  CopyablePersistent<v8::Function> const inverse;
  CopyablePersistent<v8::Function> const result;
  CopyablePersistent<v8::Value> const start;
};
class CustomTable {
 public:
  explicit CustomTable(v8::Isolate* isolate,
                       Database* db,
                       char const* name,
                       v8::Local<v8::Function> factory);
  static void Destructor(void* self);
  static sqlite3_module MODULE;
  static sqlite3_module EPONYMOUS_MODULE;

 private:
  class VTab {
    friend class CustomTable;
    explicit VTab(CustomTable* parent,
                  v8::Local<v8::Function> generator,
                  std::vector<std::string> parameter_names,
                  bool safe_ints);
    static CustomTable::VTab* Upcast(sqlite3_vtab* vtab);
    sqlite3_vtab* Downcast();
    sqlite3_vtab base;
    CustomTable* const parent;
    int const parameter_count;
    bool const safe_ints;
    CopyablePersistent<v8::Function> const generator;
    std::vector<std::string> const parameter_names;
  };
  class Cursor {
    friend class CustomTable;
    static CustomTable::Cursor* Upcast(sqlite3_vtab_cursor* cursor);
    sqlite3_vtab_cursor* Downcast();
    CustomTable::VTab* GetVTab();
    sqlite3_vtab_cursor base;
    CopyablePersistent<v8::Object> iterator;
    CopyablePersistent<v8::Function> next;
    CopyablePersistent<v8::Array> row;
    bool done;
    sqlite_int64 rowid;
  };
  class TempDataConverter : DataConverter {
    friend class CustomTable;
    explicit TempDataConverter(CustomTable* parent);
    void PropagateJSError(sqlite3_context* invocation);
    std::string GetDataErrorPrefix();
    CustomTable* const parent;
    int status;
  };
  static int xCreate(sqlite3* db_handle,
                     void* _self,
                     int argc,
                     char const* const* argv,
                     sqlite3_vtab** output,
                     char** errOutput);
  static int xConnect(sqlite3* db_handle,
                      void* _self,
                      int argc,
                      char const* const* argv,
                      sqlite3_vtab** output,
                      char** errOutput);
  static int xDisconnect(sqlite3_vtab* vtab);
  static int xOpen(sqlite3_vtab* vtab, sqlite3_vtab_cursor** output);
  static int xClose(sqlite3_vtab_cursor* cursor);
  static int xFilter(sqlite3_vtab_cursor* _cursor,
                     int idxNum,
                     char const* idxStr,
                     int argc,
                     sqlite3_value** argv);
  static int xNext(sqlite3_vtab_cursor* _cursor);
  static int xEof(sqlite3_vtab_cursor* cursor);
  static int xColumn(sqlite3_vtab_cursor* _cursor,
                     sqlite3_context* invocation,
                     int column);
  static int xRowid(sqlite3_vtab_cursor* cursor, sqlite_int64* output);
  static int xBestIndex(sqlite3_vtab* vtab, sqlite3_index_info* output);
  void PropagateJSError();
  Addon* const addon;
  v8::Isolate* const isolate;
  Database* const db;
  std::string const name;
  CopyablePersistent<v8::Function> const factory;
};
namespace Data {
v8::Local<v8::Value> GetValueJS(v8::Isolate* isolate,
                                sqlite3_stmt* handle,
                                int column,
                                bool safe_ints);
v8::Local<v8::Value> GetValueJS(v8::Isolate* isolate,
                                sqlite3_value* value,
                                bool safe_ints);
#ifdef V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetFlatRowJS(v8::Isolate* isolate,
                                  v8::Local<v8::Context> ctx,
                                  sqlite3_stmt* handle,
                                  bool safe_ints,
                                  v8::LocalVector<v8::Name>& keys);
#else  // !V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetFlatRowJS(v8::Isolate* isolate,
                                  v8::Local<v8::Context> ctx,
                                  sqlite3_stmt* handle,
                                  bool safe_ints);
#endif
v8::Local<v8::Value> GetExpandedRowJS(v8::Isolate* isolate,
                                      v8::Local<v8::Context> ctx,
                                      sqlite3_stmt* handle,
                                      bool safe_ints);
v8::Local<v8::Value> GetRawRowJS(v8::Isolate* isolate,
                                 v8::Local<v8::Context> ctx,
                                 sqlite3_stmt* handle,
                                 bool safe_ints);
#ifdef V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetRowJS(v8::Isolate* isolate,
                              v8::Local<v8::Context> ctx,
                              sqlite3_stmt* handle,
                              bool safe_ints,
                              char mode,
                              v8::LocalVector<v8::Name>& keys);
#else  // !V8_HAS_LOCAL_VECTOR
v8::Local<v8::Value> GetRowJS(v8::Isolate* isolate,
                              v8::Local<v8::Context> ctx,
                              sqlite3_stmt* handle,
                              bool safe_ints,
                              char mode);
#endif
void GetArgumentsJS(v8::Isolate* isolate,
                    v8::Local<v8::Value>* out,
                    sqlite3_value** values,
                    int argument_count,
                    bool safe_ints);
int BindValueFromJS(v8::Isolate* isolate,
                    sqlite3_stmt* handle,
                    int index,
                    v8::Local<v8::Value> value);
void ResultValueFromJS(v8::Isolate* isolate,
                       sqlite3_context* invocation,
                       v8::Local<v8::Value> value,
                       DataConverter* converter);
}  // namespace Data
class Binder {
 public:
  explicit Binder(sqlite3_stmt* _handle);
  bool Bind(v8::FunctionCallbackInfo<v8 ::Value> const& info,
            int argc,
            Statement* stmt);

 private:
  struct Result {
    int count;
    bool bound_object;
  };
  void Fail(void (*Throw)(char const*), char const* message);
  int NextAnonIndex();
  void BindValue(v8::Isolate* isolate, v8::Local<v8::Value> value, int index);
  int BindArray(v8::Isolate* isolate, v8::Local<v8::Array> arr);
  int BindObject(v8::Isolate* isolate,
                 v8::Local<v8::Object> obj,
                 Statement* stmt);
  Result BindArgs(v8::FunctionCallbackInfo<v8 ::Value> const& info,
                  int argc,
                  Statement* stmt);
  sqlite3_stmt* handle;
  int param_count;
  int anon_index;
  bool success;
};
struct Addon {
  static void JS_setErrorConstructor(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void JS_setLogHandler(
      v8::FunctionCallbackInfo<v8 ::Value> const& info);
  static void Cleanup(void* ptr);
  static void SqliteLog(void* pArg, int iErrCode, char const* zMsg);
  static void InitLoggerOnce();
  explicit Addon(v8::Isolate* isolate);
  sqlite3_uint64 NextId();
  CopyablePersistent<v8::Function> Statement;
  CopyablePersistent<v8::Function> StatementIterator;
  CopyablePersistent<v8::Function> Backup;
  CopyablePersistent<v8::Function> SqliteError;
  CopyablePersistent<v8::Function> LogHandler;
  v8::FunctionCallbackInfo<v8 ::Value> const* privileged_info;
  sqlite3_uint64 next_id;
  CS cs;
  std::set<Database*, Database::CompareDatabase> dbs;
  static uv_key_t thread_key;
};
LZZ_INLINE v8::Local<v8::String> StringFromUtf8(v8::Isolate* isolate,
                                                char const* data,
                                                int length) {
  return v8::String::NewFromUtf8(isolate, data, v8::NewStringType::kNormal,
                                 length)
      .ToLocalChecked();
}
LZZ_INLINE v8::Local<v8::String> InternalizedFromUtf8(v8::Isolate* isolate,
                                                      char const* data,
                                                      int length) {
  return v8::String::NewFromUtf8(isolate, data,
                                 v8::NewStringType::kInternalized, length)
      .ToLocalChecked();
}
LZZ_INLINE v8::Local<v8::Value> InternalizedFromUtf8OrNull(v8::Isolate* isolate,
                                                           char const* data,
                                                           int length) {
  if (data == NULL)
    return v8::Null(isolate);
  return InternalizedFromUtf8(isolate, data, length);
}
LZZ_INLINE v8::Local<v8::String> InternalizedFromLatin1(v8::Isolate* isolate,
                                                        char const* str) {
  return v8::String::NewFromOneByte(isolate,
                                    reinterpret_cast<const uint8_t*>(str),
                                    v8::NewStringType::kInternalized)
      .ToLocalChecked();
}
LZZ_INLINE void SetFrozen(v8::Isolate* isolate,
                          v8::Local<v8::Context> ctx,
                          v8::Local<v8::Object> obj,
                          CopyablePersistent<v8::String>& key,
                          v8::Local<v8::Value> value) {
  obj->DefineOwnProperty(
         ctx, key.Get(isolate), value,
         static_cast<v8::PropertyAttribute>(v8::DontDelete | v8::ReadOnly))
      .FromJust();
}
LZZ_INLINE bool IS_SKIPPED(char c) {
  return c == ' ' || c == ';' || (c >= '\t' && c <= '\r');
}
template <typename T>
LZZ_INLINE T* ALLOC_ARRAY(size_t count) {
  return static_cast<T*>(::operator new[](count * sizeof(T)));
}
template <typename T>
LZZ_INLINE void FREE_ARRAY(T* array_pointer) {
  ::operator delete[](array_pointer);
}
LZZ_INLINE int BindMap::Pair::GetIndex() {
  return index;
}
LZZ_INLINE v8::Local<v8::String> BindMap::Pair::GetName(v8::Isolate* isolate) {
  return name.Get(isolate);
}
LZZ_INLINE BindMap::Pair* BindMap::GetPairs() {
  return pairs;
}
LZZ_INLINE int BindMap::GetSize() {
  return length;
}
LZZ_INLINE void Database::AddStatement(Statement* stmt) {
  stmts.insert(stmts.end(), stmt);
}
LZZ_INLINE void Database::RemoveStatement(Statement* stmt) {
  stmts.erase(stmt);
}
LZZ_INLINE void Database::AddBackup(Backup* backup) {
  backups.insert(backups.end(), backup);
}
LZZ_INLINE void Database::RemoveBackup(Backup* backup) {
  backups.erase(backup);
}
LZZ_INLINE Database::State* Database::GetState() {
  return reinterpret_cast<State*>(&open);
}
LZZ_INLINE sqlite3* Database::GetHandle() {
  return db_handle;
}
LZZ_INLINE Addon* Database::GetAddon() {
  return addon;
}
LZZ_INLINE bool Statement::Compare(Statement const* const a,
                                   Statement const* const b) {
  return a->extras->id < b->extras->id;
}
LZZ_INLINE v8::Local<v8::Object> StatementIterator::NewRecord(
    v8::Isolate* isolate,
    v8::Local<v8::Context> ctx,
    v8::Local<v8::Value> value,
    Addon* addon,
    bool done) {
  v8::Local<v8::Object> record = v8::Object::New(isolate);
  record->Set(ctx, addon->cs.value.Get(isolate), value).FromJust();
  record->Set(ctx, addon->cs.done.Get(isolate), v8::Boolean::New(isolate, done))
      .FromJust();
  return record;
}
LZZ_INLINE v8::Local<v8::Object> StatementIterator::DoneRecord(
    v8::Isolate* isolate,
    Addon* addon) {
  return NewRecord(isolate, isolate->GetCurrentContext(),
                   v8::Undefined(isolate), addon, true);
}
LZZ_INLINE bool Backup::Compare(Backup const* const a, Backup const* const b) {
  return a->id < b->id;
}
LZZ_INLINE fts5_tokenizer* TokenizerModule::get_api_object() {
  return &api_object;
}
LZZ_INLINE fts5_tokenizer* SignalTokenizerModule::get_api_object() {
  return &api_object;
}
LZZ_INLINE void CustomAggregate::xStepBase(
    sqlite3_context* invocation,
    int argc,
    sqlite3_value** argv,
    CopyablePersistent<v8::Function> const CustomAggregate::*ptrtm) {
  CustomAggregate* self =
      static_cast<CustomAggregate*>(sqlite3_user_data(invocation));
  v8 ::Isolate* isolate = self->isolate;
  v8 ::HandleScope scope(isolate);
  Accumulator* acc = self->GetAccumulator(invocation);
  if (acc->value.IsEmpty())
    return;

  v8::Local<v8::Value> args_fast[5];
  v8::Local<v8::Value>* args =
      argc <= 4 ? args_fast : ALLOC_ARRAY<v8::Local<v8::Value>>(argc + 1);
  args[0] = acc->value.Get(isolate);
  if (argc != 0)
    Data::GetArgumentsJS(isolate, args + 1, argv, argc, self->safe_ints);

  v8::MaybeLocal<v8::Value> maybeReturnValue =
      (self->*ptrtm)
          .Get(isolate)
          ->Call(isolate->GetCurrentContext(), v8::Undefined(isolate), argc + 1,
                 args);
  if (args != args_fast)
    delete[] args;

  if (maybeReturnValue.IsEmpty()) {
    self->PropagateJSError(invocation);
  } else {
    v8::Local<v8::Value> returnValue = maybeReturnValue.ToLocalChecked();
    if (!returnValue->IsUndefined())
      acc->value.Reset(isolate, returnValue);
  }
}
LZZ_INLINE void CustomAggregate::xValueBase(sqlite3_context* invocation,
                                            bool is_final) {
  CustomAggregate* self =
      static_cast<CustomAggregate*>(sqlite3_user_data(invocation));
  v8 ::Isolate* isolate = self->isolate;
  v8 ::HandleScope scope(isolate);
  Accumulator* acc = self->GetAccumulator(invocation);
  if (acc->value.IsEmpty())
    return;

  if (!is_final) {
    acc->is_window = true;
  } else if (acc->is_window) {
    DestroyAccumulator(invocation);
    return;
  }

  v8::Local<v8::Value> result = acc->value.Get(isolate);
  if (self->invoke_result) {
    v8::MaybeLocal<v8::Value> maybeResult = self->result.Get(isolate)->Call(
        isolate->GetCurrentContext(), v8::Undefined(isolate), 1, &result);
    if (maybeResult.IsEmpty()) {
      self->PropagateJSError(invocation);
      return;
    }
    result = maybeResult.ToLocalChecked();
  }

  Data::ResultValueFromJS(isolate, invocation, result, self);
  if (is_final)
    DestroyAccumulator(invocation);
}
LZZ_INLINE CustomTable::VTab* CustomTable::VTab::Upcast(sqlite3_vtab* vtab) {
  return reinterpret_cast<VTab*>(vtab);
}
LZZ_INLINE sqlite3_vtab* CustomTable::VTab::Downcast() {
  return reinterpret_cast<sqlite3_vtab*>(this);
}
LZZ_INLINE CustomTable::Cursor* CustomTable::Cursor::Upcast(
    sqlite3_vtab_cursor* cursor) {
  return reinterpret_cast<Cursor*>(cursor);
}
LZZ_INLINE sqlite3_vtab_cursor* CustomTable::Cursor::Downcast() {
  return reinterpret_cast<sqlite3_vtab_cursor*>(this);
}
LZZ_INLINE CustomTable::VTab* CustomTable::Cursor::GetVTab() {
  return VTab::Upcast(base.pVtab);
}
LZZ_INLINE sqlite3_uint64 Addon::NextId() {
  return next_id++;
}
#undef LZZ_INLINE
#endif
