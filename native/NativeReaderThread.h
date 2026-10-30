#pragma once
#include "ContextAdapter.h"
#include <pthread.h>
namespace titan_inventory {
// Exact original stop code compares pthread_self() with InputThread+0x40,
// reached through InputReader+0x50. Invoke only while the outer lifecycle owner
// guarantees this original Reader/thread storage remains live and not stopping.
inline bool nativeReaderThread(const void* reader) noexcept {
 if(!titan_runtime::aligned(reader))return false;
 const void* thread=titan_runtime::field<const void*>(reader,0x50);
 if(!titan_runtime::aligned(thread))return false;
 const auto original=titan_runtime::field<uint64_t>(thread,0x40);
 const pthread_t self=pthread_self();static_assert(sizeof(self)==sizeof(uint64_t));
 uint64_t current;std::memcpy(&current,&self,sizeof(current));return original==current;
}
}
