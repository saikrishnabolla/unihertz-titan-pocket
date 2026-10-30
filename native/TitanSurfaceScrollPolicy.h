#pragma once
#include <cmath>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace titan_surface {
using Time = int64_t; // monotonic nanoseconds
struct Identity {
    int32_t rawId;
    std::string name;
    bool isInternal;
    bool hasMtPosition;
};
// Bind a discovered raw subdevice, never its aggregate Android device id.
inline bool isSurface(const Identity& d) {
    return d.name == "mtk-pad" && d.isInternal && d.hasMtPosition;
}
struct Key {
    int32_t rawId;
    int32_t scanCode;
    bool down;
    bool repeat;
};
class TypingGuard {
public:
    explicit TypingGuard(int32_t typingRawId) : mRawId(typingRawId) {}
    bool key(Time now, const Key& key) {
        if (key.rawId != mRawId) return false;
        if (key.down) mHeld.insert(key.scanCode);
        else mHeld.erase(key.scanCode);
        mLastActivity = std::max(mLastActivity, now); // repeat uses event time, never original downTime
        return true;
    }
    void removed(Time now, int32_t rawId) {
        if (rawId == mRawId) { mHeld.clear(); mLastActivity = std::max(mLastActivity, now); mPresent = false; }
    }
    bool blocked(Time now, Time cooldown) const {
        return !mPresent || !mHeld.empty() ||
                (mLastActivity != std::numeric_limits<Time>::min() &&
                 (now < mLastActivity || static_cast<uint64_t>(now) - static_cast<uint64_t>(mLastActivity) <
                         static_cast<uint64_t>(cooldown)));
    }
private:
    int32_t mRawId;
    bool mPresent = true;
    Time mLastActivity = std::numeric_limits<Time>::min();
    std::set<int32_t> mHeld;
};
struct Contact { int32_t id; float x; float y; bool palm = false; };
struct Frame { Time when; std::vector<Contact> contacts; bool valid = true; };
enum class Action { Down, Move, Up, Cancel };
struct Motion { Action action; Time when; Time downTime; float x; float y; };
struct Config {
    float pixelsPerRawX;
    float pixelsPerRawY;
    float startSlopPixels;
    Time typingCooldown;
    float rawMinX, rawMaxX, rawMinY, rawMaxY;
    bool valid() const {
        const double spanX = static_cast<double>(rawMaxX) - rawMinX;
        const double spanY = static_cast<double>(rawMaxY) - rawMinY;
        const double max = std::numeric_limits<float>::max();
        return std::isfinite(pixelsPerRawX) && pixelsPerRawX > 0 &&
                std::isfinite(pixelsPerRawY) && pixelsPerRawY > 0 &&
                std::isfinite(startSlopPixels) && startSlopPixels >= 0 && typingCooldown >= 0 &&
                std::isfinite(rawMinX) && std::isfinite(rawMaxX) &&
                std::isfinite(rawMinY) && std::isfinite(rawMaxY) && spanX > 0 && spanY > 0 &&
                spanX * pixelsPerRawX <= max && spanY * pixelsPerRawY <= max;
    }
};
class Policy {
public:
    Policy(Identity surface, TypingGuard& typing, Config config)
          : mIdentity(std::move(surface)), mTyping(typing), mConfig(config) {}
    bool enabled() const { return isSurface(mIdentity) && mConfig.valid(); }
    // Call immediately on an accepted keyboard event, even without a surface frame.
    std::vector<Motion> typing(Time now) {
        if (!enabled()) return {};
        return interrupt(now);
    }
    std::vector<Motion> setAllowed(Time now, bool allowed) {
        if (mAllowed == allowed) return {};
        mAllowed = allowed;
        return interrupt(now);
    }
    // Also used for display change/loss, capture-mode change, SYN_DROPPED, reset and removal.
    std::vector<Motion> interrupt(Time now) {
        std::vector<Motion> out;
        if (mActive) out.push_back(motion(Action::Cancel, now));
        mActive = false;
        mContact = false;
        mBlockedUntilLift = true;
        return out;
    }
    std::vector<Motion> frame(const Frame& frame) {
        if (!enabled()) return {};
        if (frame.when < 0 || frame.when < mLastFrame || frame.when < mLastOutput) return interrupt(mLastFrame);
        mLastFrame = frame.when;
        if (!frame.valid) return interrupt(frame.when);
        if (frame.contacts.empty()) {
            std::vector<Motion> out;
            if (mActive) out.push_back(motion(Action::Up, frame.when));
            mActive = false;
            mContact = false;
            mBlockedUntilLift = false;
            return out;
        }
        if (!mAllowed) return interrupt(frame.when);
        if (mBlockedUntilLift) return {};
        if (mTyping.blocked(frame.when, mConfig.typingCooldown) ||
            frame.contacts.size() != 1 || frame.contacts[0].palm ||
            !std::isfinite(frame.contacts[0].x) || !std::isfinite(frame.contacts[0].y) ||
            frame.contacts[0].x < mConfig.rawMinX || frame.contacts[0].x > mConfig.rawMaxX ||
            frame.contacts[0].y < mConfig.rawMinY || frame.contacts[0].y > mConfig.rawMaxY) {
            return interrupt(frame.when);
        }
        const Contact& contact = frame.contacts[0];
        if (mContact && contact.id != mTrackingId) return interrupt(frame.when);
        if (!mContact) {
            mTrackingId = contact.id;
            mOriginX = mLastX = contact.x;
            mOriginY = mLastY = contact.y;
            mX = mY = 0;
            mContact = true;
            return {};
        }
        const float totalX = static_cast<float>((static_cast<double>(contact.x) - mOriginX) *
                                                mConfig.pixelsPerRawX);
        const float totalY = static_cast<float>((static_cast<double>(contact.y) - mOriginY) *
                                                mConfig.pixelsPerRawY);
        if (!std::isfinite(totalX) || !std::isfinite(totalY)) return interrupt(frame.when);
        if (!mActive) {
            if (std::hypot(totalX, totalY) <= mConfig.startSlopPixels) return {};
            mDownTime = frame.when;
            mActive = true;
            std::vector<Motion> out{motion(Action::Down, frame.when)};
            mX = totalX; mY = totalY;
            mLastX = contact.x; mLastY = contact.y;
            out.push_back(motion(Action::Move, frame.when));
            return out;
        }
        const bool unchanged = totalX == mX && totalY == mY;
        mLastX = contact.x; mLastY = contact.y;
        if (unchanged) return {};
        mX = totalX; mY = totalY;
        return {motion(Action::Move, frame.when)};
    }
private:
    Motion motion(Action action, Time when) {
        mLastOutput = std::max(when, mLastOutput);
        return {action, mLastOutput, mDownTime, mX, mY};
    }
    Identity mIdentity;
    TypingGuard& mTyping;
    Config mConfig;
    bool mAllowed = true;
    bool mActive = false;
    bool mContact = false;
    bool mBlockedUntilLift = false;
    int32_t mTrackingId = 0;
    Time mLastFrame = std::numeric_limits<Time>::min();
    Time mDownTime = 0;
    Time mLastOutput = 0;
    float mOriginX = 0, mOriginY = 0, mLastX = 0, mLastY = 0, mX = 0, mY = 0;
};
} // namespace titan_surface
