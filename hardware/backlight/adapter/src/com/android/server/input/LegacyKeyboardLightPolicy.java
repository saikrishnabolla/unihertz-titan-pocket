/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.input;

/** Single-handler policy; requests do not prove physical illumination. */
final class LegacyKeyboardLightPolicy {
    enum Result { NONE, REQUESTED, NO_HAL, ERROR }
    interface Sink { Result request(boolean on); }
    interface Clock { long nowMs(); }

    private final boolean mTargetDevice;
    private final Sink mSink;
    private final Clock mClock;
    private boolean mModernLightPresent = true;
    private boolean mInteractive;
    private boolean mEnabled = true;
    private boolean mAmbientPolicy;
    private boolean mLuxKnown;
    private float mLux;
    private boolean mArmed;
    private boolean mFaulted;
    private long mTimeoutMs = 3000;
    private long mLastActivityMs;
    private long mLastNowMs = -1;
    private Boolean mLastRequestedOn;
    private Result mLastResult = Result.NONE;

    LegacyKeyboardLightPolicy(String device, String platform, String kernel, Clock clock, Sink sink) {
        if (clock == null || sink == null) throw new IllegalArgumentException("clock and sink required");
        mTargetDevice = matches(device, platform, kernel);
        mClock = clock;
        mSink = sink;
    }

    static boolean matches(String device, String platform, String kernel) {
        return "Titan_pocket".equals(device) && "mt6771".equals(platform)
                && "4.14.186-g40b2a1864-dirty".equals(kernel);
    }

    void setModernLightPresent(boolean present) {
        long now = advance();
        mModernLightPresent = present;
        if (present) disarm();
        apply(now);
    }

    void setInteractive(boolean interactive) {
        long now = advance();
        mInteractive = interactive;
        if (!interactive) disarm();
        apply(now);
    }

    void setEnabled(boolean enabled) {
        long now = advance();
        mEnabled = enabled;
        if (!enabled) disarm();
        apply(now);
    }

    void setTimeoutMs(long timeoutMs) {
        long now = advance();
        mTimeoutMs = timeoutMs;
        if (timeoutMs == 0) mArmed = false;
        apply(now);
    }

    void setAmbientPolicy(boolean enabled) {
        long now = advance();
        if (mAmbientPolicy != enabled) mLuxKnown = false;
        mAmbientPolicy = enabled;
        apply(now);
    }

    void sensorLux(float lux) {
        long now = advance();
        if (mAmbientPolicy) {
            mLuxKnown = !Float.isNaN(lux) && !Float.isInfinite(lux) && lux >= 0;
            if (mLuxKnown) mLux = lux;
        }
        apply(now);
    }

    void activity() {
        long now = advance();
        if (eligible() && mTimeoutMs != 0) {
            mArmed = true;
            mLastActivityMs = now;
        }
        apply(now);
    }

    void onDeadline() { apply(advance()); }

    // The adapter calls onDeadline at this absolute monotonic time, or on any later wake.
    long nextDeadlineMs() {
        return !mFaulted && eligible() && mArmed && mTimeoutMs > 0 ? deadline() : -1;
    }

    Result lastResult() { return mLastResult; }
    boolean requestedOn() { return Boolean.TRUE.equals(mLastRequestedOn); }
    boolean faulted() { return mFaulted; }

    private boolean eligible() {
        return !mFaulted && mTargetDevice && mEnabled && !mModernLightPresent && mInteractive;
    }

    private void disarm() { mArmed = false; mLuxKnown = false; }

    private long deadline() {
        return mTimeoutMs > Long.MAX_VALUE - mLastActivityMs
                ? Long.MAX_VALUE : mLastActivityMs + mTimeoutMs;
    }

    private void expire(long now) {
        if (mArmed && mTimeoutMs > 0 && now >= deadline()) mArmed = false;
    }

    private long advance() {
        if (mFaulted) return mLastNowMs;
        try {
            long now = mClock.nowMs();
            if (now < 0 || now < mLastNowMs) {
                failClock();
                return mLastNowMs;
            }
            mLastNowMs = now;
            expire(now);
            return now;
        } catch (RuntimeException | LinkageError error) {
            failClock();
            return mLastNowMs;
        }
    }

    private void failClock() {
        boolean cleanup = Boolean.TRUE.equals(mLastRequestedOn);
        fail();
        if (!cleanup) return;
        try {
            if (mSink.request(false) == Result.REQUESTED) mLastRequestedOn = false;
        } catch (RuntimeException | LinkageError error) {
            // Fault remains latched; the last successful request is still ON.
        }
    }

    private void fail() { mFaulted = true; mArmed = false; mLastResult = Result.ERROR; }

    private void apply(long now) {
        if (!mTargetDevice || mFaulted) return;
        expire(now);
        boolean on = eligible() && mArmed && mTimeoutMs != 0
                && (!mAmbientPolicy || (mLuxKnown && mLux < 50.0f));
        if (Boolean.valueOf(on).equals(mLastRequestedOn)
                || (!on && mLastRequestedOn == null)) return;
        try {
            Result result = mSink.request(on);
            if (result == Result.REQUESTED) mLastRequestedOn = on;
            if (result == null || result == Result.NONE || result == Result.ERROR) fail();
            else mLastResult = result;
        } catch (RuntimeException | LinkageError error) {
            fail();
        }
    }
}
