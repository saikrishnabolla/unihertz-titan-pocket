#include "NativeMotionAdapter.h"
#include <array>
#include <cmath>

namespace titan_native {
bool NativeMotionAdapter::emit(const MotionInput& input) const noexcept {
    if (!listener_ || !owner_ || !validate_ || !calls_.motionConstruct ||
        !calls_.motionDestroy || !calls_.queueConstruct || !calls_.queueNotifyMotion ||
        !calls_.queueFlush || !calls_.queueDestroy || !calls_.setAxisValue ||
        input.pointers.empty() || input.pointers.size() > MAX_POINTERS) return false;

    // Validate all structure before any native call. Meaning and permitted values
    // of these fields remain the supplied validator's responsibility.
    for (size_t i = 0; i < input.pointers.size(); ++i) {
        const auto& pointer = input.pointers[i];
        if (pointer.axes.size() > android::PointerCoords::MAX_AXES) return false;
        for (size_t j = 0; j < i; ++j)
            if (input.pointers[j].properties.id == pointer.properties.id) return false;
        uint64_t seen = 0;
        for (const auto& axis : pointer.axes) {
            if (axis.axis < 0 || axis.axis >= 64 || !std::isfinite(axis.value)) return false;
            const uint64_t bit = uint64_t{1} << axis.axis;
            if (seen & bit) return false;
            seen |= bit;
        }
    }
    if (!validate_(input, validationContext_)) return false;

    std::array<android::PointerProperties, MAX_POINTERS> properties{};
    std::array<android::PointerCoords, MAX_POINTERS> coords{};
    for (size_t i = 0; i < input.pointers.size(); ++i) {
        properties[i] = input.pointers[i].properties;
        // Zero initialization covers values and explicit padding as well as bits.
        coords[i].clear();
        for (const auto& axis : input.pointers[i].axes)
            if (calls_.setAxisValue(&coords[i], axis.axis, axis.value) != 0) return false;
        coords[i].isResampled = input.pointers[i].isResampled;
    }

    alignas(8) std::byte motion[160];
    alignas(8) std::byte queue[40];
    calls_.motionConstruct(motion, input.id, input.eventTime, input.readTime, input.deviceId,
        input.source, input.displayId, input.policyFlags, input.action, input.actionButton,
        input.motionFlags, input.metaState, input.buttonState, input.classification,
        static_cast<uint32_t>(input.pointers.size()), properties.data(), coords.data(),
        input.xPrecision, input.yPrecision, input.xCursorPosition, input.yCursorPosition,
        input.downTime, input.videoFrames);
    calls_.queueConstruct(queue, listener_);
    calls_.queueNotifyMotion(queue, motion); // Original notify deep-copies motion.
    calls_.motionDestroy(motion);
    calls_.queueFlush(queue); // Exactly one original flush for this generated event.
    calls_.queueDestroy(queue);
    return true;
}
}
