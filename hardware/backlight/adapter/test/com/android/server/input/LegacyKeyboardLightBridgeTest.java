package com.android.server.input;

import android.content.Context;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.lights.LightsManager;
import com.android.server.lights.LogicalLight;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class LegacyKeyboardLightBridgeTest {
    private static final String TIMEOUT = "keyboard_bl_timeout";
    private static final String AMBIENT = "key_keyboard_backlight_base_on_brightness";
    static final class Light extends LogicalLight {
        final List<Float> writes = new ArrayList<>();
        boolean throwOff;
        int color;
        int hardwareBrightness;
        public void setBrightness(float value) {
            int brightness = Math.round(1.0f + value * 254.0f);
            writes.add(1.0f);
            color = 0xff000000 | brightness << 16 | brightness << 8 | brightness;
            hardwareBrightness = (color & 0x00ffffff) == 0 ? 0 : 255;
        }
        public void setColor(int color) { throw new AssertionError("unexpected color"); }
        public void setFlashing(int c, int m, int on, int off) { throw new AssertionError("unexpected flash"); }
        public void turnOff() {
            writes.add(0.0f);
            if (throwOff) throw new LinkageError("light off");
            color = 0;
            hardwareBrightness = 0;
        }
    }
    static final class Manager extends LightsManager {
        Light light;
        final List<Integer> ids = new ArrayList<>();
        Manager(Light light) { this.light = light; }
        public LogicalLight getLight(int id) { ids.add(id); if (id != 2) throw new AssertionError("non-Buttons light"); return light; }
        public void setMutedState(boolean muted) { throw new AssertionError("unexpected mute"); }
    }
    static final class Fixture {
        final Context context = new Context();
        final Handler handler = new Handler();
        final Light light = new Light();
        final Manager manager = new Manager(light);
        LegacyKeyboardLightBridge bridge;
        Fixture() {
            SystemClock.now = 0; SystemClock.reads = 0;
            SystemProperties.values.clear();
            SystemProperties.values.put("ro.product.vendor.device", "Titan_pocket");
            SystemProperties.values.put("ro.board.platform", "mt6771");
            Os.release = "4.14.186-g40b2a1864-dirty"; Os.fail = false;
            LocalServices.services.clear(); LocalServices.gets = 0; LocalServices.fail = false;
            LocalServices.services.put(LightsManager.class, manager);
            Looper.current = handler.looper;
        }
        void build() { bridge = new LegacyKeyboardLightBridge(context, handler); }
        void ready() { build(); bridge.setModernLightPresent(false); }
        void writes(Float... values) { equal(light.writes, Arrays.asList(values)); }
        void deadline(long when) { equal(handler.queue.size(), 1); equal(handler.queue.get(0).when, when); }
        void noneScheduled() { equal(handler.queue.size(), 0); }
        void failed(String reason) { contains(bridge.toString(), "disabled=true"); contains(bridge.toString(), reason); }
    }
    static void equal(Object value, Object expected) { if (!value.equals(expected)) throw new AssertionError("expected " + expected + ", got " + value); }
    static void contains(String value, String expected) { if (!value.contains(expected)) throw new AssertionError("missing " + expected + " in " + value); }
    static void yes(boolean value) { if (!value) throw new AssertionError("expected true"); }
    static void no(boolean value) { if (value) throw new AssertionError("expected false"); }

    public static void main(String[] args) {
        Fixture f = new Fixture(); f.build(); yes(f.bridge.isTargetDevice());
        equal(f.context.resolverCalls, 0); equal(f.context.serviceCalls, 0); equal(f.handler.removals, 0);
        f.bridge.activity(true); f.writes(); equal(f.context.resolverCalls, 0);
        f.bridge.setModernLightPresent(false); equal(f.context.resolver.registrations, 2);
        equal(f.context.resolver.reads, 2); equal(f.context.serviceCalls, 0);
        f.bridge.activity(true); f.writes(1.0f); f.deadline(3000);
        f.handler.runUntil(2999); f.writes(1.0f); f.handler.runUntil(3000); f.writes(1.0f, 0.0f);
        f.noneScheduled(); equal(f.manager.ids, Arrays.asList(2, 2));
        System.out.println("PASS lazy inventory setup; default deadline and Buttons-only standard light requests");

        Light zeroBrightness = new Light(); zeroBrightness.setBrightness(0.0f);
        equal(zeroBrightness.color, 0xff010101); equal(zeroBrightness.hardwareBrightness, 255);
        zeroBrightness.turnOff(); equal(zeroBrightness.color, 0); equal(zeroBrightness.hardwareBrightness, 0);
        f = new Fixture(); f.ready(); f.bridge.activity(true); equal(f.light.hardwareBrightness, 255);
        f.bridge.interactive(false); equal(f.light.color, 0); equal(f.light.hardwareBrightness, 0);
        f.bridge.interactive(true); f.bridge.activity(true); equal(f.light.hardwareBrightness, 255);
        f.handler.runUntil(3000); equal(f.light.color, 0); equal(f.light.hardwareBrightness, 0);
        System.out.println("PASS zero float brightness stays lit; explicit off clears RGB on screen-off and idle");

        f = new Fixture(); f.ready(); f.bridge.activity(true);
        SystemClock.now = 2999; f.bridge.activity(true); f.deadline(5999); f.writes(1.0f);
        f.handler.runUntil(3000); f.writes(1.0f);
        f.context.resolver.change(TIMEOUT, 0); f.writes(1.0f, 0.0f); f.noneScheduled();
        f.context.resolver.change(TIMEOUT, -1); f.bridge.activity(true); f.writes(1.0f, 0.0f, 1.0f); f.noneScheduled();
        f.handler.runUntil(100000); f.writes(1.0f, 0.0f, 1.0f);
        f.context.resolver.change(TIMEOUT, 3000); f.writes(1.0f, 0.0f, 1.0f, 0.0f); f.noneScheduled();
        System.out.println("PASS activity refresh and live settings observers for zero/negative/positive timeouts");

        f = new Fixture(); f.context.resolver.values.put(AMBIENT, 1L); f.ready();
        equal(f.context.sensor.registrations, 0); f.bridge.activity(true);
        equal(f.context.sensor.registrations, 1); f.writes(); f.deadline(3000);
        f.context.sensor.emit(49); f.writes(1.0f); f.context.sensor.emit(50); f.writes(1.0f, 0.0f);
        f.context.sensor.emit(Float.NaN); f.writes(1.0f, 0.0f); f.context.sensor.emit(1); f.writes(1.0f, 0.0f, 1.0f);
        f.bridge.interactive(false); f.writes(1.0f, 0.0f, 1.0f, 0.0f);
        equal(f.context.sensor.unregistrations, 1); f.noneScheduled();
        f.bridge.interactive(true); f.bridge.activity(true); f.writes(1.0f, 0.0f, 1.0f, 0.0f);
        equal(f.context.sensor.registrations, 2); f.context.sensor.emit(1); f.writes(1.0f, 0.0f, 1.0f, 0.0f, 1.0f);
        System.out.println("PASS ambient unknown/off threshold and fresh sensor lifecycle across screen-off");

        f = new Fixture(); f.context.resolver.values.put(AMBIENT, 1L); f.ready(); f.bridge.activity(true);
        f.context.sensor.emit(1); final SensorEventListener old = f.context.sensor.listener;
        Looper.current = new Looper(); old.onSensorChanged(new SensorEvent(f.context.sensor.sensor, 1));
        Looper.current = f.handler.looper; f.bridge.setModernLightPresent(true);
        f.writes(1.0f, 0.0f); equal(f.context.sensor.unregistrations, 1);
        f.handler.runUntil(0); f.writes(1.0f, 0.0f);
        f.bridge.setModernLightPresent(false); old.onSensorChanged(new SensorEvent(f.context.sensor.sensor, 1));
        f.bridge.activity(true); f.writes(1.0f, 0.0f); f.context.sensor.emit(1); f.writes(1.0f, 0.0f, 1.0f);
        System.out.println("PASS modern takeover releases; queued/stale sensor generations cannot relight");

        f = new Fixture(); f.ready(); f.bridge.activity(true); f.context.resolver.change(AMBIENT, 1);
        f.writes(1.0f, 0.0f); equal(f.context.sensor.registrations, 1);
        f.context.sensor.emit(1); f.writes(1.0f, 0.0f, 1.0f);
        f.context.resolver.change(AMBIENT, 0); equal(f.context.sensor.unregistrations, 1);
        f.writes(1.0f, 0.0f, 1.0f); f.bridge.disableAfterError();
        f.writes(1.0f, 0.0f, 1.0f, 0.0f); f.noneScheduled(); equal(f.context.resolver.unregistrations, 1);
        f.bridge.activity(true); f.writes(1.0f, 0.0f, 1.0f, 0.0f);
        System.out.println("PASS ambient setting changes and explicit disable stop subscriptions and deadlines");

        for (int missing = 0; missing < 3; missing++) {
            f = new Fixture(); f.context.resolver.values.put(AMBIENT, 1L);
            if (missing == 0) f.context.sensor = null;
            if (missing == 1) f.context.sensor.sensor = null;
            if (missing == 2) f.context.sensor.reject = true;
            f.ready(); f.bridge.activity(true); f.writes(); f.deadline(3000);
            f.context.resolver.change(AMBIENT, 0); f.writes(1.0f);
        }
        f = new Fixture(); f.ready(); LocalServices.services.clear(); f.bridge.activity(true);
        f.writes(); contains(f.bridge.toString(), "lastResult=NO_HAL");
        LocalServices.services.put(LightsManager.class, f.manager); f.bridge.activity(true); f.writes(1.0f);
        f.manager.light = null; f.bridge.interactive(false); f.writes(1.0f);
        contains(f.bridge.toString(), "requestedOn=true"); contains(f.bridge.toString(), "physicalUnknown=true");
        System.out.println("PASS missing/rejected sensors remain unknown; absent light services report NO_HAL");

        f = new Fixture(); f.context.resolver.failRegistrationAt = 2; f.build(); f.bridge.setModernLightPresent(false);
        f.failed("adapter-error"); equal(f.context.resolver.unregistrations, 1);
        equal(f.context.resolver.observers.size(), 0); f.writes(); f.noneScheduled();
        f.bridge.activity(true); f.writes();
        f = new Fixture(); f.ready(); f.bridge.activity(true); f.context.resolver.failRead = true;
        f.context.resolver.change(TIMEOUT, 10); f.failed("adapter-error"); f.writes(1.0f, 0.0f); f.noneScheduled();
        System.out.println("PASS partial observer setup and live settings read failures clean up safely");

        f = new Fixture(); f.ready(); f.bridge.activity(true); f.context.sensor.throwRegister = true;
        f.context.resolver.change(AMBIENT, 1); f.failed("adapter-error"); f.writes(1.0f, 0.0f); f.noneScheduled();
        f = new Fixture(); f.context.resolver.values.put(AMBIENT, 1L); f.ready(); f.bridge.activity(true);
        f.context.sensor.emit(1); f.context.sensor.throwUnregister = true; f.bridge.setModernLightPresent(true);
        f.failed("adapter-error"); f.writes(1.0f, 0.0f); f.noneScheduled(); f.context.sensor.emit(1); f.writes(1.0f, 0.0f);
        System.out.println("PASS sensor setup/release exceptions contained without stale relight");

        f = new Fixture(); f.ready(); f.handler.rejectDeadline = true; f.bridge.activity(true);
        f.failed("adapter-error"); f.writes(1.0f, 0.0f); f.noneScheduled(); f.bridge.activity(true); f.writes(1.0f, 0.0f);
        f = new Fixture(); f.ready(); f.bridge.activity(true); f.handler.throwRemove = true;
        f.bridge.disableAfterError(); f.writes(1.0f, 0.0f); f.failed("cancel-error");
        f.handler.runUntil(5000); f.writes(1.0f, 0.0f);
        System.out.println("PASS deadline post/cancel failures disable; already queued callbacks cannot reactivate");

        f = new Fixture(); f.ready(); f.bridge.activity(true); f.light.throwOff = true;
        f.bridge.interactive(false); f.writes(1.0f, 0.0f); f.failed("policy-error");
        contains(f.bridge.toString(), "requestedOn=true"); contains(f.bridge.toString(), "lastResult=ERROR");
        equal(f.light.hardwareBrightness, 255);
        f.bridge.activity(true); f.bridge.disableAfterError(); f.writes(1.0f, 0.0f); f.noneScheduled();
        f = new Fixture(); f.ready(); LocalServices.fail = true; f.bridge.activity(true);
        f.failed("policy-error"); f.writes(); f.noneScheduled();
        System.out.println("PASS sink faults preserve uncertainty and do not add recursive cleanup retries");

        f = new Fixture(); f.ready(); SystemClock.now = 10; f.bridge.activity(true);
        SystemClock.now = 9; f.bridge.activity(true); f.writes(1.0f, 0.0f); f.failed("policy-error");
        f.noneScheduled(); SystemClock.now = 100; f.bridge.activity(true); f.writes(1.0f, 0.0f);
        f = new Fixture(); f.ready(); SystemClock.now = 10; f.bridge.activity(true); f.light.throwOff = true;
        SystemClock.now = 9; f.bridge.interactive(false); f.writes(1.0f, 0.0f); f.failed("policy-error");
        contains(f.bridge.toString(), "requestedOn=true"); f.bridge.disableAfterError(); f.writes(1.0f, 0.0f);
        System.out.println("PASS core clock cleanup remains one-shot through adapter fault handling");

        f = new Fixture(); f.ready(); f.bridge.activity(true);
        String before = f.bridge.toString(); int reads = SystemClock.reads; int removals = f.handler.removals;
        SystemClock.now = 4000; Looper.current = new Looper(); equal(f.bridge.toString(), before);
        equal(SystemClock.reads, reads); equal(f.handler.removals, removals); f.writes(1.0f);
        f.bridge.interactive(false); f.writes(1.0f); f.handler.runUntil(4000); f.writes(1.0f, 0.0f);
        System.out.println("PASS dump is read-only; off-thread entry queues all policy/light mutations");

        f = new Fixture(); f.ready(); f.bridge.activity(true); Looper.current = new Looper();
        f.handler.rejectPost = true; f.bridge.interactive(false); f.writes(1.0f);
        contains(f.bridge.toString(), "cleanup=not-run"); contains(f.bridge.toString(), "physicalUnknown=true");
        f.handler.runUntil(3000); f.writes(1.0f, 0.0f); f.failed("dispatch-error"); f.noneScheduled();
        System.out.println("PASS rejected cross-thread dispatch reports uncertainty; next handler callback cleans up once");

        for (int wrong = 0; wrong < 4; wrong++) {
            f = new Fixture();
            if (wrong == 0) SystemProperties.values.put("ro.product.vendor.device", "other");
            if (wrong == 1) SystemProperties.values.put("ro.board.platform", "other");
            if (wrong == 2) Os.release = "other";
            if (wrong == 3) Os.fail = true;
            f.build(); no(f.bridge.isTargetDevice()); f.bridge.setModernLightPresent(false);
            f.bridge.activity(true); f.bridge.interactive(false); f.bridge.disableAfterError(); f.bridge.toString();
            equal(f.context.resolverCalls, 0); equal(f.context.serviceCalls, 0); equal(LocalServices.gets, 0);
            equal(f.handler.removals, 0); equal(f.handler.posts, 0); f.writes(); f.noneScheduled();
        }
        System.out.println("PASS wrong target/identity failure has no observer, sensor, handler or light side effects");
    }
}
