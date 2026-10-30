package com.android.server.input;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class LegacyKeyboardLightPolicyTest {
    static final class Fixture implements LegacyKeyboardLightPolicy.Clock, LegacyKeyboardLightPolicy.Sink {
        long now;
        final List<Boolean> writes = new ArrayList<>();
        LegacyKeyboardLightPolicy.Result response = LegacyKeyboardLightPolicy.Result.REQUESTED;
        boolean throwsError;
        boolean clockThrows;
        final LegacyKeyboardLightPolicy policy;
        Fixture() { this("Titan_pocket", "mt6771", "4.14.186-g40b2a1864-dirty"); }
        Fixture(String model, String platform, String kernel) {
            policy = new LegacyKeyboardLightPolicy(model, platform, kernel, this, this);
        }
        public long nowMs() { if (clockThrows) throw new IllegalStateException("test clock failure"); return now; }
        public LegacyKeyboardLightPolicy.Result request(boolean on) {
            writes.add(on);
            if (throwsError) throw new LinkageError("test callback failure");
            return response;
        }
        void ready() { policy.setInteractive(true); policy.setModernLightPresent(false); }
        void writes(Boolean... expected) { equal(writes, Arrays.asList(expected)); }
    }
    static void equal(Object actual, Object expected) {
        if (!actual.equals(expected)) throw new AssertionError("expected " + expected + ", got " + actual);
    }
    static void yes(boolean value) { if (!value) throw new AssertionError("expected true"); }
    static void no(boolean value) { if (value) throw new AssertionError("expected false"); }

    public static void main(String[] args) {
        Fixture f = new Fixture(); f.ready(); f.writes(); f.policy.activity(); f.writes(true);
        equal(f.policy.nextDeadlineMs(), 3000L);
        f.now = 2999; f.policy.activity(); equal(f.policy.nextDeadlineMs(), 5999L); f.writes(true);
        f.now = 3000; f.policy.onDeadline(); f.writes(true);
        f.now = 5998; f.policy.onDeadline(); yes(f.policy.requestedOn());
        f.now = 5999; f.policy.onDeadline(); f.writes(true, false); equal(f.policy.nextDeadlineMs(), -1L);
        f.now = 6000; f.policy.onDeadline(); f.writes(true, false);
        System.out.println("PASS default 3000ms, typing refresh, stale callback and exact expiration");

        f = new Fixture(); f.ready(); f.policy.setTimeoutMs(0); f.policy.activity(); f.writes();
        f.policy.setTimeoutMs(-1); f.writes(); f.policy.activity(); f.writes(true); equal(f.policy.nextDeadlineMs(), -1L);
        f.now = 1000000; f.policy.onDeadline(); f.writes(true);
        f.policy.setInteractive(false); f.writes(true, false);
        f.policy.setInteractive(true); f.writes(true, false); f.policy.activity(); f.writes(true, false, true);
        f.policy.setTimeoutMs(0); f.writes(true, false, true, false); equal(f.policy.nextDeadlineMs(), -1L);
        System.out.println("PASS zero disables; negative stays on until screen-off; reentry needs activity");

        f = new Fixture(); f.ready(); f.policy.activity(); f.now = 1000; f.policy.setTimeoutMs(5000);
        equal(f.policy.nextDeadlineMs(), 5000L); f.now = 4999; f.policy.onDeadline(); f.writes(true);
        f.policy.setTimeoutMs(-2); equal(f.policy.nextDeadlineMs(), -1L);
        f.now = 6000; f.policy.setTimeoutMs(3000); f.writes(true, false);
        f.policy.setTimeoutMs(-1); f.writes(true, false); f.policy.activity(); f.writes(true, false, true);
        f.now = 7000; f.policy.setTimeoutMs(500); f.writes(true, false, true, false);
        System.out.println("PASS timeout transitions recompute from last activity without reviving expiry");

        f = new Fixture(); f.ready(); f.policy.activity(); f.now = 3000; f.policy.setTimeoutMs(-1);
        f.writes(true, false); equal(f.policy.nextDeadlineMs(), -1L);
        f.policy.activity(); f.writes(true, false, true);
        System.out.println("PASS setting changed at exact old deadline does not revive expired activity");

        f = new Fixture(); f.ready(); f.policy.setAmbientPolicy(true); f.policy.activity(); f.writes();
        equal(f.policy.nextDeadlineMs(), 3000L); f.policy.sensorLux(49.9f); f.writes(true);
        f.policy.sensorLux(50.0f); f.writes(true, false); f.policy.sensorLux(0); f.writes(true, false, true);
        f.policy.sensorLux(Float.NaN); f.writes(true, false, true, false);
        f.policy.sensorLux(Float.POSITIVE_INFINITY); f.policy.sensorLux(-1); f.writes(true, false, true, false);
        f.policy.sensorLux(1); f.writes(true, false, true, false, true);
        f.now = 3000; f.policy.sensorLux(0); f.writes(true, false, true, false, true, false);
        f.policy.activity(); f.writes(true, false, true, false, true, false, true);
        System.out.println("PASS unknown/invalid lux off, strict lux<50, sensor never extends deadline");

        f = new Fixture(); f.ready(); f.policy.sensorLux(1); f.policy.activity(); f.writes(true);
        f.policy.setAmbientPolicy(true); f.writes(true, false);
        f.policy.sensorLux(10); f.writes(true, false, true);
        f.policy.setAmbientPolicy(false); f.policy.sensorLux(1000); f.writes(true, false, true);
        f.policy.setAmbientPolicy(true); f.writes(true, false, true, false);
        System.out.println("PASS ambient defaults off; enabling always waits for a fresh sensor reading");

        for (int gate = 0; gate < 2; gate++) {
            f = new Fixture(); f.ready(); f.policy.setTimeoutMs(-1); f.policy.activity();
            if (gate == 0) f.policy.setEnabled(false);
            if (gate == 1) f.policy.setModernLightPresent(true);
            f.writes(true, false); equal(f.policy.nextDeadlineMs(), -1L); f.policy.activity();
            f.policy.setEnabled(true); f.policy.setModernLightPresent(false);
            f.writes(true, false); f.policy.activity(); f.writes(true, false, true);
        }
        System.out.println("PASS explicit disable and modern takeover release and discard stale activity");

        f = new Fixture(); f.policy.setModernLightPresent(false); f.policy.setInteractive(true);
        f.policy.activity(); f.writes(true); equal(f.policy.nextDeadlineMs(), 3000L);
        f.policy.setInteractive(false); f.writes(true, false);
        System.out.println("PASS interactive lock-screen typing lights without consuming any unlock metadata");

        f = new Fixture(); f.policy.setInteractive(true); f.policy.activity(); f.writes();
        f.policy.setModernLightPresent(false); f.writes(); f.policy.activity(); f.writes(true);
        String[][] mismatches = {{"Titan", "mt6771", "4.14.186-g40b2a1864-dirty"},
            {"Titan_pocket", "mt6768", "4.14.186-g40b2a1864-dirty"},
            {"Titan_pocket", "mt6771", "4.14.186"}, {null, "mt6771", "4.14.186-g40b2a1864-dirty"}};
        for (String[] values : mismatches) {
            f = new Fixture(values[0], values[1], values[2]); f.ready(); f.policy.activity(); f.writes();
            equal(f.policy.nextDeadlineMs(), -1L);
        }
        System.out.println("PASS conservative modern-inventory gate and exact model/platform/kernel guard");

        f = new Fixture(); f.ready(); f.response = LegacyKeyboardLightPolicy.Result.NO_HAL;
        f.policy.activity(); no(f.policy.requestedOn()); equal(f.policy.lastResult(), LegacyKeyboardLightPolicy.Result.NO_HAL);
        f.response = LegacyKeyboardLightPolicy.Result.REQUESTED; f.now = 10; f.policy.activity(); f.writes(true, true);
        f.response = LegacyKeyboardLightPolicy.Result.NO_HAL; f.now = 3010; f.policy.onDeadline(); f.writes(true, true, false);
        f.response = LegacyKeyboardLightPolicy.Result.REQUESTED; f.policy.onDeadline(); f.writes(true, true, false, false);
        no(f.policy.requestedOn());
        System.out.println("PASS absent HAL retries on later callbacks and failed off request remains retryable");

        f = new Fixture(); f.ready(); f.policy.activity(); f.throwsError = true; f.policy.setInteractive(false);
        yes(f.policy.faulted()); equal(f.policy.lastResult(), LegacyKeyboardLightPolicy.Result.ERROR);
        equal(f.policy.nextDeadlineMs(), -1L); f.policy.setInteractive(true); f.policy.activity(); f.policy.onDeadline();
        f.writes(true, false); yes(f.policy.requestedOn());
        for (LegacyKeyboardLightPolicy.Result result : new LegacyKeyboardLightPolicy.Result[] {
                LegacyKeyboardLightPolicy.Result.ERROR, LegacyKeyboardLightPolicy.Result.NONE, null}) {
            f = new Fixture(); f.ready(); f.response = result; f.policy.activity();
            yes(f.policy.faulted()); f.policy.activity(); f.writes(true);
        }
        System.out.println("PASS callback faults contained, latched and never misreported as successful off");

        f = new Fixture(); f.now = Long.MAX_VALUE - 100; f.ready(); f.policy.activity();
        equal(f.policy.nextDeadlineMs(), Long.MAX_VALUE); f.now = Long.MAX_VALUE - 1;
        f.policy.onDeadline(); f.writes(true); f.now = Long.MAX_VALUE; f.policy.onDeadline(); f.writes(true, false);
        f = new Fixture(); f.ready(); f.now = 10; f.policy.activity(); f.now = 9; f.policy.onDeadline();
        yes(f.policy.faulted()); equal(f.policy.nextDeadlineMs(), -1L); f.writes(true, false); no(f.policy.requestedOn());
        f.policy.setInteractive(false); f.policy.setInteractive(true); f.policy.activity(); f.policy.onDeadline(); f.writes(true, false);
        System.out.println("PASS deadline saturation and one successful clock-fault cleanup with no later requests");

        for (int failure = 0; failure < 3; failure++) {
            f = new Fixture(); f.ready(); f.policy.activity();
            f.clockThrows = true;
            if (failure == 0) f.response = LegacyKeyboardLightPolicy.Result.NO_HAL;
            if (failure == 1) f.throwsError = true;
            if (failure == 2) f.response = LegacyKeyboardLightPolicy.Result.ERROR;
            f.policy.onDeadline(); f.writes(true, false); yes(f.policy.requestedOn());
            yes(f.policy.faulted()); equal(f.policy.lastResult(), LegacyKeyboardLightPolicy.Result.ERROR);
            equal(f.policy.nextDeadlineMs(), -1L);
            f.policy.setInteractive(false); f.policy.setEnabled(false);
            f.policy.activity(); f.policy.onDeadline(); f.writes(true, false);
        }
        f = new Fixture(); f.ready(); f.clockThrows = true; f.policy.activity(); f.writes();
        yes(f.policy.faulted()); equal(f.policy.nextDeadlineMs(), -1L);
        System.out.println("PASS thrown-clock cleanup tried once; failed cleanup stays uncertain and faulted; no cleanup before ON");
    }
}
