#pragma once
#include <input/Input.h>
#include <input/TouchVideoFrame.h>
#include <ftl/flags.h>
#include <cstddef>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

namespace android { enum class PolicyFlag : uint32_t; }
namespace titan_native {
static_assert(sizeof(android::PointerProperties) == 8 && alignof(android::PointerProperties) == 4);
static_assert(offsetof(android::PointerProperties, id) == 0);
static_assert(offsetof(android::PointerProperties, toolType) == 4);
static_assert(sizeof(android::PointerCoords) == 136 && alignof(android::PointerCoords) == 8);
static_assert(offsetof(android::PointerCoords, bits) == 0);
static_assert(offsetof(android::PointerCoords, values) == 8);
static_assert(offsetof(android::PointerCoords, isResampled) == 128);
static_assert(sizeof(android::ui::LogicalDisplayId) == 4);
static_assert(sizeof(android::ftl::Flags<android::PolicyFlag>) == 4);
static_assert(sizeof(android::ftl::Flags<android::MotionFlag>) == 4);
static_assert(!std::is_trivially_copy_constructible_v<android::ftl::Flags<android::PolicyFlag>>);
static_assert(!std::is_trivially_copy_constructible_v<android::ftl::Flags<android::MotionFlag>>);
static_assert(sizeof(android::MotionClassification) == 1);
static_assert(sizeof(std::vector<android::TouchVideoFrame>) == 24);

// Exact declaration retained from motion_probe.cpp. Both Flags parameters are
// nontrivial C++ values and must retain their native indirect argument ABI.
using MotionConstructor = void(*)(void*, int32_t, int64_t, int64_t, int32_t, uint32_t,
    android::ui::LogicalDisplayId, android::ftl::Flags<android::PolicyFlag>, int32_t, int32_t,
    android::ftl::Flags<android::MotionFlag>, int32_t, int32_t,
    android::MotionClassification, uint32_t, const android::PointerProperties*,
    const android::PointerCoords*, float, float, float, float, int64_t,
    const std::vector<android::TouchVideoFrame>&);
struct NativeCalls {
    MotionConstructor motionConstruct;
    void (*motionDestroy)(void*); // Original D2; never delete sidecar storage.
    void (*queueConstruct)(void*, void*); // Original listener reference in x1.
    void (*queueNotifyMotion)(void*, const void*);
    void (*queueFlush)(void*);
    void (*queueDestroy)(void*); // Original D2.
    android::status_t (*setAxisValue)(android::PointerCoords*, int32_t, float);
};
struct AxisValue { int32_t axis; float value; };
struct PointerInput {
    android::PointerProperties properties;
    std::span<const AxisValue> axes;
    bool isResampled;
};
// Every event value is caller input; this layer allocates no IDs or timestamps,
// chooses no source, display, flags, tool, action, precision or cursor sentinel.
struct MotionInput {
    int32_t id;
    int64_t eventTime;
    int64_t readTime;
    int32_t deviceId;
    uint32_t source;
    android::ui::LogicalDisplayId displayId;
    android::ftl::Flags<android::PolicyFlag> policyFlags;
    int32_t action;
    int32_t actionButton;
    android::ftl::Flags<android::MotionFlag> motionFlags;
    int32_t metaState;
    int32_t buttonState;
    android::MotionClassification classification;
    std::span<const PointerInput> pointers;
    float xPrecision;
    float yPrecision;
    float xCursorPosition;
    float yCursorPosition;
    int64_t downTime;
    const std::vector<android::TouchVideoFrame>& videoFrames;
};
// The integration must validate the full event against authoritative production
// identity/stream/display/value policy. Structural checks alone cannot authorize it.
using ValueValidator = bool(*)(const MotionInput&, const void* context) noexcept;

class NativeMotionAdapter final {
public:
    NativeMotionAdapter(NativeCalls calls, void* listener, std::shared_ptr<const void> owner,
                        ValueValidator validate, const void* validationContext)
        : calls_(calls), listener_(listener), owner_(std::move(owner)),
          validate_(validate), validationContext_(validationContext) {}
    // Call synchronously from the endpoint's authorized dispatch gate, outside
    // Reader mutex, on a callback thread proven valid by the eventual integration.
    // Caller must retain the adapter and input storage for the full call and keep
    // their contents stable. Original callbacks must return normally without throw.
    bool emit(const MotionInput& input) const noexcept;
private:
    NativeCalls calls_;
    void* listener_;
    // This token must enforce the original Reader/listener lifetime contract.
    // A borrowed listener address alone provides no ownership proof.
    std::shared_ptr<const void> owner_;
    ValueValidator validate_;
    const void* validationContext_;
};
}
