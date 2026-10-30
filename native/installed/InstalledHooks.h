#pragma once
#include <cstdint>
#include <memory>
namespace titan_installed {
struct ContextCalls {
    int32_t (*getNextId)(const void* readerContext);
    int32_t (*getGlobalMetaState)(void* readerContext);
    const void* touchpadVtable;
    const void* keyboardVtable;
};
struct ResetCalls {
    void (*construct)(void* storage,int32_t id,int64_t eventTime,int32_t deviceId);
    void (*notify)(void* queuedListener,const void* resetArgs);
};
class InstalledHooks final {
public:
    uintptr_t base() const noexcept {return base_;}
    const ContextCalls& context() const noexcept {return context_;}
    const ResetCalls& reset() const noexcept {return reset_;}
private:
    friend std::shared_ptr<const InstalledHooks> resolveInstalledHooks() noexcept;
    InstalledHooks(uintptr_t b,ContextCalls c,ResetCalls r,std::shared_ptr<const void> m)
        :base_(b),context_(c),reset_(r),module_(std::move(m)){}
    const uintptr_t base_;
    const ContextCalls context_;
    const ResetCalls reset_;
    const std::shared_ptr<const void> module_;
};
// Retain this immutable proof for every use. This checks installed code and
// original calls; it does not authorize a device or prove any Reader lifetime.
// Original context getters require a live generation and the original Reader
// lock. Reset storage/listener/event validity remain the caller's responsibility.
std::shared_ptr<const InstalledHooks> resolveInstalledHooks() noexcept;
}
