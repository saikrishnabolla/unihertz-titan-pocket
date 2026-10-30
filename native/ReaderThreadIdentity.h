#pragma once
#include <memory>
#include <pthread.h>
#include <thread>
namespace titan_surface {
// A retained token distinguishes a retired thread from a later reused thread id.
// The extension must stay loaded until pthread-key destructors have finished.
class ReaderThreadIdentity final {
    inline static pthread_once_t once = PTHREAD_ONCE_INIT;
    inline static pthread_key_t key;
    inline static int error = 0;
    static void destroy(void* p) { delete static_cast<std::shared_ptr<const char>*>(p); }
    static void initialize() { error = pthread_key_create(&key, destroy); }
    static std::shared_ptr<const char> current() {
        if (pthread_once(&once, initialize) || error) return {};
        auto* p = static_cast<std::shared_ptr<const char>*>(pthread_getspecific(key));
        if (!p) {
            p = new std::shared_ptr<const char>(std::make_shared<const char>(0));
            if (pthread_setspecific(key, p)) { delete p; return {}; }
        }
        return *p;
    }
    const std::thread::id thread = std::this_thread::get_id();
    const std::shared_ptr<const char> token = current();
public:
    bool isOwner() const { return token && thread == std::this_thread::get_id() && token == current(); }
};
}
