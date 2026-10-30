#include "RuntimePrerequisites.h"
#include <dlfcn.h>
namespace titan_runtime {
std::shared_ptr<const RuntimePrerequisites> resolveRuntimePrerequisites()noexcept {
 auto hooks=titan_installed::resolveInstalledHooks();if(!hooks)return {};
 auto originals=titan_resolver::resolveOriginalApis();if(!originals||!originals->modules)return {};
 auto metadata=resolveOriginalMetadata();if(!metadata)return {};
 Dl_info queue{};
 if(!dladdr(reinterpret_cast<const void*>(originals->native.queueConstruct),&queue)||
    reinterpret_cast<uintptr_t>(queue.dli_fbase)!=hooks->base()||
    metadata->readerContextVtable!=originals->policy.readerVtable)return {};
 return std::make_shared<const RuntimePrerequisites>(RuntimePrerequisites{std::move(*originals),*metadata,std::move(hooks)});
}
}
