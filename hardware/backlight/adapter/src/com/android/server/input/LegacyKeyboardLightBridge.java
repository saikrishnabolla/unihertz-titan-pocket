/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.input;

import android.content.ContentResolver;
import android.content.Context;
import android.database.ContentObserver;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.provider.Settings;
import android.system.Os;

import com.android.server.LocalServices;
import com.android.server.lights.LightsManager;
import com.android.server.lights.LogicalLight;

/** Handler-owned adapter; the dump string is an immutable snapshot. */
final class LegacyKeyboardLightBridge {
    private static final String TIMEOUT = "keyboard_bl_timeout";
    private static final String AMBIENT = "key_keyboard_backlight_base_on_brightness";
    private final Context mContext;
    private final Handler mHandler;
    private final boolean mTarget;
    private final LegacyKeyboardLightPolicy mPolicy;
    private ContentResolver mResolver;
    private ContentObserver mObserver;
    private SensorManager mSensorManager;
    private SensorEventListener mSensorListener;
    private boolean mObserverRegistered;
    private boolean mSensorRegistered;
    private boolean mInitialized;
    private boolean mDisabled;
    private boolean mModern = true;
    private boolean mInteractive;
    private boolean mAmbient;
    private boolean mButtonsPresent;
    private long mTimeout = 3000;
    private long mDeadline = -1;
    private String mFailure = "none";
    private volatile boolean mDispatchFailed;
    private volatile String mSnapshot = "Titan legacy lights: target=false hardwareVerified=false";
    private final Runnable mDeadlineCallback;

    LegacyKeyboardLightBridge(Context context, Handler handler) {
        mContext = context;
        mHandler = handler;
        boolean target = false;
        try {
            target = LegacyKeyboardLightPolicy.matches(
                    SystemProperties.get("ro.product.vendor.device"),
                    SystemProperties.get("ro.board.platform"), Os.uname().release);
        } catch (RuntimeException | LinkageError error) {
            // An unavailable identity disables this device-specific fallback.
        }
        LegacyKeyboardLightPolicy policy = null;
        if (target) {
            try {
                policy = new LegacyKeyboardLightPolicy("Titan_pocket", "mt6771",
                        "4.14.186-g40b2a1864-dirty", SystemClock::uptimeMillis, this::requestButtons);
            } catch (RuntimeException | LinkageError error) {
                target = false;
            }
        }
        mTarget = target;
        mPolicy = policy;
        mDeadlineCallback = () -> guarded(() -> mPolicy.onDeadline());
        if (target) mSnapshot = "Titan legacy lights: target=true initialized=false hardwareVerified=false";
    }

    boolean isTargetDevice() { return mTarget; }

    void setModernLightPresent(boolean present) {
        dispatch(() -> {
            mModern = present;
            mPolicy.setModernLightPresent(present);
            if (!mInitialized) initialize();
        });
    }

    void activity(boolean interactive) {
        dispatch(() -> {
            mInteractive = interactive;
            mPolicy.setInteractive(interactive);
            if (mInitialized && interactive) mPolicy.activity();
        });
    }

    void interactive(boolean interactive) {
        dispatch(() -> {
            mInteractive = interactive;
            mPolicy.setInteractive(interactive);
        });
    }

    void disableAfterError() { dispatch(() -> disable("external-error", true)); }

    @Override
    public String toString() { return mSnapshot; }

    private void dispatch(Runnable action) {
        if (!mTarget) return;
        try {
            if (mHandler == null) throw new IllegalStateException("missing handler");
            if (Looper.myLooper() == mHandler.getLooper()) guarded(action);
            else if (!mHandler.post(() -> guarded(action))) dispatchFailed();
        } catch (RuntimeException | LinkageError error) {
            dispatchFailed();
        }
    }

    private void dispatchFailed() {
        mDispatchFailed = true;
        mSnapshot = "Titan legacy lights: target=true failure=dispatch-error cleanup=not-run"
                + " physicalUnknown=true hardwareVerified=false";
    }

    private void guarded(Runnable action) {
        if (mDisabled) return;
        try {
            if (mDispatchFailed) {
                disable("dispatch-error", true);
                return;
            }
            action.run();
            if (mDisabled) return;
            if (mPolicy.faulted()) {
                disable("policy-error", false);
                return;
            }
            updateSensor();
            if (mPolicy.faulted()) disable("policy-error", false);
            else scheduleDeadline();
        } catch (RuntimeException | LinkageError error) {
            disable("adapter-error", true);
        } finally {
            snapshot();
        }
    }

    private void initialize() {
        mResolver = mContext.getContentResolver();
        mObserver = new ContentObserver(mHandler) {
            @Override public void onChange(boolean selfChange) { dispatch(() -> readSettings()); }
            @Override public void onChange(boolean selfChange, Uri uri) { dispatch(() -> readSettings()); }
        };
        // Mark before the first registration so partial setup is also cleaned up.
        mObserverRegistered = true;
        mResolver.registerContentObserver(Settings.Global.getUriFor(TIMEOUT), false, mObserver);
        mResolver.registerContentObserver(Settings.Global.getUriFor(AMBIENT), false, mObserver);
        readSettings();
        mInitialized = true;
    }

    private void readSettings() {
        mTimeout = Settings.Global.getLong(mResolver, TIMEOUT, 3000);
        mAmbient = Settings.Global.getInt(mResolver, AMBIENT, 0) != 0;
        mPolicy.setTimeoutMs(mTimeout);
        mPolicy.setAmbientPolicy(mAmbient);
    }

    private void updateSensor() {
        boolean wanted = mInitialized && !mDisabled && !mModern && mInteractive
                && mAmbient && mTimeout != 0;
        if (!wanted) {
            stopSensor();
            return;
        }
        if (mSensorRegistered) return;
        if (mSensorManager == null) {
            mSensorManager = (SensorManager) mContext.getSystemService(Context.SENSOR_SERVICE);
        }
        if (mSensorManager == null) return;
        final Sensor sensor = mSensorManager.getDefaultSensor(Sensor.TYPE_LIGHT);
        if (sensor == null) return;
        final SensorEventListener listener = new SensorEventListener() {
            @Override public void onSensorChanged(SensorEvent event) {
                try {
                    if (event == null || event.sensor != sensor) return;
                    final float lux = event.values == null || event.values.length == 0
                            ? Float.NaN : event.values[0];
                    dispatch(() -> {
                        if (mSensorRegistered && mSensorListener == this) mPolicy.sensorLux(lux);
                    });
                } catch (RuntimeException | LinkageError error) {
                    dispatch(() -> disable("sensor-callback-error", true));
                }
            }
            @Override public void onAccuracyChanged(Sensor changed, int accuracy) { }
        };
        mSensorListener = listener;
        mSensorRegistered = mSensorManager.registerListener(listener, sensor,
                SensorManager.SENSOR_DELAY_NORMAL, mHandler);
        if (!mSensorRegistered) {
            mSensorListener = null;
            mSensorManager.unregisterListener(listener);
        }
    }

    private void stopSensor() {
        SensorEventListener old = mSensorListener;
        mSensorListener = null;
        mSensorRegistered = false;
        if (old != null && mSensorManager != null) mSensorManager.unregisterListener(old);
        if (mAmbient) mPolicy.sensorLux(Float.NaN);
    }

    private void scheduleDeadline() {
        mHandler.removeCallbacks(mDeadlineCallback);
        mDeadline = mPolicy.nextDeadlineMs();
        if (mDeadline >= 0 && !mHandler.postAtTime(mDeadlineCallback, mDeadline)) {
            throw new IllegalStateException("deadline rejected");
        }
    }

    private LegacyKeyboardLightPolicy.Result requestButtons(boolean on) {
        LightsManager manager = LocalServices.getService(LightsManager.class);
        LogicalLight buttons = manager == null ? null : manager.getLight(2);
        mButtonsPresent = buttons != null;
        if (buttons == null) return LegacyKeyboardLightPolicy.Result.NO_HAL;
        if (on) buttons.setBrightness(1.0f);
        else buttons.turnOff();
        return LegacyKeyboardLightPolicy.Result.REQUESTED;
    }

    private void disable(String failure, boolean release) {
        if (mDisabled) return;
        mDisabled = true;
        mFailure = failure;
        mDeadline = -1;
        try { mHandler.removeCallbacks(mDeadlineCallback); }
        catch (RuntimeException | LinkageError error) { mFailure += ":cancel-error"; }
        if (release && !mPolicy.faulted()) mPolicy.setEnabled(false);
        try { stopSensor(); }
        catch (RuntimeException | LinkageError error) { mFailure += ":sensor-release-error"; }
        if (mObserverRegistered) {
            mObserverRegistered = false;
            try { mResolver.unregisterContentObserver(mObserver); }
            catch (RuntimeException | LinkageError error) { mFailure += ":observer-release-error"; }
        }
    }

    private void snapshot() {
        mSnapshot = "Titan legacy lights: target=" + mTarget + " initialized=" + mInitialized
                + " disabled=" + mDisabled + " failure=" + mFailure
                + " interactive=" + mInteractive + " modern=" + mModern
                + " ambient=" + mAmbient + " sensorRegistered=" + mSensorRegistered
                + " deadline=" + mDeadline + " buttonsPresent=" + mButtonsPresent
                + " lastResult=" + mPolicy.lastResult() + " requestedOn=" + mPolicy.requestedOn()
                + " physicalUnknown=true hardwareVerified=false";
    }
}
