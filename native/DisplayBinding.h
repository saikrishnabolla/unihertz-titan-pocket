#pragma once
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
namespace titan_display {
struct MapperState {
    int32_t associatedId;
    float left, top, right, bottom; // inclusive native converter bounds
    uint32_t inputRotation;
};
struct ViewportFields {
    int32_t displayId;
    uint32_t rotation;
    int32_t left, top, right, bottom; // exclusive Android logical right/bottom
    bool active;
};
struct Binding {
    int32_t associatedId; // -1 is native focused/default display association
    int32_t displayId;   // resolved concrete viewport ID
    int32_t logicalLeft, logicalTop, logicalRight, logicalBottom;
    float left, top, right, bottom;
    uint32_t displayRotation, inputRotation;
    friend bool operator==(const Binding&, const Binding&) = default;
};
template<class T> inline T field(const void *p, size_t off) noexcept {
    T out; std::memcpy(&out,static_cast<const unsigned char*>(p)+off,sizeof(out));return out;
}
inline bool aligned(const void *p) noexcept {return p && reinterpret_cast<uintptr_t>(p)%8==0;}
// All four objects/vtables must already be authenticated and retained by the
// caller under the original Reader mutex. This function cannot validate lifetimes.
inline std::optional<MapperState> readMapper(const void *mapper, const void *context,
        const void *readerContext, const void *mapperVtable) noexcept {
    if (!aligned(mapper)||!aligned(context)||!aligned(readerContext)||!aligned(mapperVtable))return {};
    if (field<const void*>(mapper,0)!=mapperVtable||field<const void*>(mapper,8)!=context||
        field<const void*>(context,16)!=readerContext)return {};
    // Unknown capture enum values also disable the extension.
    if (field<int32_t>(mapper,0x480)!=0)return {};
    const auto present=field<uint8_t>(mapper,0x4e4);
    const auto duplicatePresent=field<uint8_t>(mapper,0x110);
    if (present!=1||duplicatePresent!=1)return {};
    const auto associatedId=field<int32_t>(mapper,0x4e0);
    if (associatedId < -1 || associatedId != field<int32_t>(mapper,0x10c))return {};
    MapperState s{associatedId,field<float>(mapper,0x114),field<float>(mapper,0x118),
        field<float>(mapper,0x11c),field<float>(mapper,0x120),field<uint32_t>(mapper,0x124)};
    if (!std::isfinite(s.left)||!std::isfinite(s.top)||!std::isfinite(s.right)||!std::isfinite(s.bottom)||
        s.right<=s.left||s.bottom<=s.top||s.inputRotation>3)return {};
    return s;
}
inline std::optional<Binding> validate(const MapperState& m,const ViewportFields& v) noexcept {
    if (!v.active||v.displayId<0||v.rotation>3||m.associatedId < -1||
        (m.associatedId>=0&&m.associatedId!=v.displayId)||v.right<=v.left||v.bottom<=v.top)return {};
    const int64_t width=static_cast<int64_t>(v.right)-v.left;
    const int64_t height=static_cast<int64_t>(v.bottom)-v.top;
    // Integer frame edges must remain exactly representable as native float coords.
    constexpr int32_t maxExact=1<<24;
    for (auto edge : {v.left,v.top,v.right,v.bottom})if(edge < -maxExact || edge>maxExact)return {};
    if (width<=1||height<=1)return {};
    const uint32_t inverse=(4-v.rotation)%4;
    const float left=static_cast<float>(v.left),top=static_cast<float>(v.top);
    const float right=static_cast<float>(static_cast<int64_t>(v.right)-1);
    const float bottom=static_cast<float>(static_cast<int64_t>(v.bottom)-1);
    if (m.inputRotation!=inverse||m.left!=left||m.top!=top||m.right!=right||m.bottom!=bottom)return {};
    return Binding{m.associatedId,v.displayId,v.left,v.top,v.right,v.bottom,
        left,top,right,bottom,v.rotation,inverse};
}
} // namespace titan_display
