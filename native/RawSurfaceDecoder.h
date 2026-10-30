#pragma once
#include "scoped-binding-adapter.h"
#include "TitanSurfaceScrollPolicy.h"
#include "proven/mapper/accumulator/MultiTouchMotionAccumulator.h"
#ifndef SYN_REPORT
#define SYN_REPORT 0
#define SYN_DROPPED 3
#define EV_KEY 1
#define ABS_X 0
#define BTN_TOUCH 330
#define BTN_TOOL_FINGER 325
#endif
#include <array>
#include <cstddef>

namespace titan_surface {
static_assert(sizeof(android::RawEvent) == 32);
static_assert(offsetof(android::RawEvent, when) == 0);
static_assert(offsetof(android::RawEvent, readTime) == 8);
static_assert(offsetof(android::RawEvent, deviceId) == 16);
static_assert(offsetof(android::RawEvent, type) == 20);
static_assert(offsetof(android::RawEvent, code) == 24);
static_assert(offsetof(android::RawEvent, value) == 28);

// All registration pointers must remain alive for the entire call, under the reader's lock.
// The owner must call reset/removal immediately and send every returned frame to Policy.
class RawSurfaceDecoder {
public:
    RawSurfaceDecoder(titan_cp3_probe::Registration registration,
                      titan_cp3_probe::Callbacks callbacks, std::string descriptor)
        : mRegistration(registration), mCallbacks(callbacks), mDescriptor(std::move(descriptor)),
          mAuthorized(titan_cp3_probe::bind(registration, callbacks, mDescriptor)) {
        mAccumulator.configure(mOfflineContext, kSlots, false);
    }
    bool authorized() const { return mAuthorized && !mRemoved; }
    std::optional<Frame> consume(const titan_cp3_probe::Registration& current,
                                 const void* bytes, size_t size) {
        if (!authorized()) return {};
        if (!sameRegistration(current) ||
            !titan_cp3_probe::bind(current, mCallbacks, mDescriptor)) {
            mRemoved = true;
            return invalidate(mLastTime, true);
        }
        // Reject foreign input before reading type/code/value, including all typing input.
        if (!bytes || size != sizeof(android::RawEvent)) return invalidate(mLastTime, true);
        if (titan_cp3_probe::readField<int32_t>(bytes, 16) != mRegistration.rawId) return {};
        auto parsed = titan_cp3_probe::rawEvent(bytes, size, mRegistration.rawId);
        if (!parsed) return invalidate(mLastTime, true);
        const auto& event = *parsed;
        if (event.when < mLastTime) return invalidate(mLastTime, true);
        mLastTime = event.when;
        if (event.type == EV_SYN && event.code == SYN_DROPPED) {
            mDiscardThroughReport = true;
            return invalidate(event.when);
        }
        if (mDiscardThroughReport) {
            if (event.type == EV_SYN && event.code == SYN_REPORT) mDiscardThroughReport = false;
            return {};
        }
        if (event.type == EV_SYN && event.code == SYN_REPORT) {
            if (event.value != 0) mMalformed = true;
            return finish(event.when);
        }
        if (event.type == EV_SYN && event.code == SYN_MT_REPORT) {
            if (event.value != 0 || mPacket >= kSlots) mMalformed = true;
            else ++mPacket;
        } else if (event.type == EV_ABS) {
            if (mPacket >= kSlots) mMalformed = true;
            else {
                auto& p = mPackets[mPacket];
                p.any = true; ++p.axes;
                switch (event.code) {
                case ABS_MT_TRACKING_ID:
                    if (p.tracking || event.value < -1 || event.value > 10) mMalformed = true;
                    p.tracking = true; p.id = event.value; break;
                case ABS_MT_POSITION_X:
                    if (p.x || event.value < 0 || event.value > 720) mMalformed = true;
                    p.x = true; break;
                case ABS_MT_POSITION_Y:
                    if (p.y || event.value < 0 || event.value > 360) mMalformed = true;
                    p.y = true; break;
                case ABS_MT_TOUCH_MAJOR: case ABS_MT_TOUCH_MINOR:
                    if (event.value < 0 || event.value > 100) mMalformed = true;
                    break;
                default: mMalformed = true; break;
                }
            }
        } else if (event.type == EV_KEY &&
                   (event.code == BTN_TOUCH || event.code == BTN_TOOL_FINGER)) {
            if (event.value != 0 && event.value != 1) mMalformed = true;
            if (event.code == BTN_TOUCH) { mHaveTouch = true; mTouch = event.value == 1; }
            mButtonActivity = true;
        } else {
            // This captured device uses complete protocol-A packets. Keys and other SYN
            // codes cannot establish an empty contact frame or supply missing coordinates.
            mMalformed = true;
        }
        if (!mMalformed) mAccumulator.process(event);
        return {};
    }
    Frame reset(Time when) {
        mDiscardThroughReport = true;
        return invalidate(when);
    }
    Frame removal(Time when) {
        mRemoved = true;
        return invalidate(when);
    }
private:
    static constexpr size_t kSlots = 16;
    struct Packet { bool any = false, tracking = false, x = false, y = false; int id = -1; size_t axes = 0; };
    bool sameRegistration(const titan_cp3_probe::Registration& r) const {
        return r.live && r.mapper == mRegistration.mapper && r.context == mRegistration.context &&
               r.owner == mRegistration.owner && r.rawId == mRegistration.rawId &&
               r.generation == mRegistration.generation &&
               r.contextVtableAddressPoint == mRegistration.contextVtableAddressPoint &&
               r.mapperVtableAddressPoint == mRegistration.mapperVtableAddressPoint;
    }
    void clearFrame() {
        mAccumulator.finishSync();
        mPackets = {}; mPacket = 0; mMalformed = false; mButtonActivity = false;
    }
    Frame invalidate(Time when, bool discard = false) {
        mDiscardThroughReport = mDiscardThroughReport || discard;
        mLastTime = std::max(mLastTime, when);
        clearFrame(); mAwaitLift = true; mHaveTouch = false; mTouch = false;
        return {mLastTime, {}, false};
    }
    Frame finish(Time when) {
        Frame result{when, {}, true};
        for (size_t i = 0; i < kSlots; ++i) {
            const auto& p = mPackets[i];
            if (!p.any) continue;
            // Every nonempty packet must end with SYN_MT_REPORT. A lift packet has
            // tracking id -1 only; all live packets carry fresh X/Y and tracking id.
            if (i >= mPacket || !p.tracking ||
                (p.id < 0 ? (p.axes != 1) : (!p.x || !p.y))) mMalformed = true;
            if (p.id >= 0) {
                for (const auto& previous : result.contacts)
                    if (previous.id == p.id) mMalformed = true;
                const auto& slot = mAccumulator.getSlot(i);
                if (!slot.isInUse() || slot.getTrackingId() != p.id) mMalformed = true;
                result.contacts.push_back({p.id, static_cast<float>(slot.getX()),
                    static_cast<float>(slot.getY()), slot.getToolType() == titan_cp3_protocol::ToolType::PALM});
            } else if (!result.contacts.empty()) mMalformed = true;
        }
        // Mixed lift/live packets are ambiguous for this device's protocol.
        for (const auto& p : mPackets)
            if (p.any && p.id < 0 && !result.contacts.empty()) mMalformed = true;
        if (mHaveTouch && mTouch != !result.contacts.empty()) mMalformed = true;
        if (mButtonActivity && result.contacts.empty() && (!mHaveTouch || mTouch)) mMalformed = true;
        if (mMalformed) return invalidate(when);
        clearFrame();
        if (result.contacts.empty()) mAwaitLift = false;
        else if (mAwaitLift) result.valid = false;
        return result;
    }
    titan_cp3_probe::Registration mRegistration;
    titan_cp3_probe::Callbacks mCallbacks;
    std::string mDescriptor;
    bool mAuthorized = false, mRemoved = false, mAwaitLift = false;
    bool mDiscardThroughReport = false, mMalformed = false;
    bool mHaveTouch = false, mTouch = false, mButtonActivity = false;
    Time mLastTime = 0;
    size_t mPacket = 0;
    std::array<Packet, kSlots> mPackets{};
    // Only protocol-A configuration is used; no EventHub slot queries occur.
    titan_cp3_protocol::InputDeviceContext mOfflineContext;
    titan_cp3_protocol::MultiTouchMotionAccumulator mAccumulator;
};
}
