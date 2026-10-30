#pragma once
#include <cstdint>
#include <cstddef>
namespace titan_native_owner {
// Android ARM64 heap pointers carry a top-byte tag; maps lists address bits only.
// Keep the original pointer for every memory access and identity comparison.
inline uintptr_t mappingAddress(uintptr_t address,bool arm64Tagged)noexcept {
 return arm64Tagged ? address & UINT64_C(0x00ffffffffffffff) : address;
}
inline bool readableMappingContains(uintptr_t address,size_t size,uintptr_t lo,
                                    uintptr_t hi,bool readable,bool arm64Tagged)noexcept {
 const auto mapped=mappingAddress(address,arm64Tagged);
 return address&&mapped&&size&&readable&&lo<=mapped&&mapped<hi&&size<=hi-mapped;
}
}
