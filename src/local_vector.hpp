#ifndef SRC_LOCAL_VECTOR_H_
#define SRC_LOCAL_VECTOR_H_

#include <node.h>

// See: https://github.com/v8/v8/commit/e1649301dfbfd34a448c3a0232c8a6206b716c73
// Required V8 verison: 12.0.54 or higher

#if V8_MAJOR_VERSION > 12 ||     \
    V8_MINOR_VERSION == 12 &&    \
        (V8_MINOR_VERSION > 0 || \
         V8_MINOR_VERSION == 0 && V8_PATCH_VERSION >= 54)

template <class T>
class LocalVector : public v8::LocalVector<T> {
 public:
  LocalVector(v8::Isolate* isolate) : v8::LocalVector<T>(isolate) {}

  inline bool is_supported() { return true; }
};

#else

template <class T>
class LocalVector {
 public:
  LocalVector(v8::Isolate* isolate) {}

  inline void reserve(size_t size) {}
  inline size_t size() { return 0; }
  inline void emplace_back(v8::Local<T> value) { abort(); }
  inline v8::Local<T>* data() { abort(); }

  inline bool is_supported() { return false; }
};

#endif

#endif  // SRC_LOCAL_VECTOR_H_
