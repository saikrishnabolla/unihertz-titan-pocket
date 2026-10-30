package com.android.server.input;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public final class ProductionSessionStateTest {
    private static int checks;
    private static void check(boolean value) {
        ++checks;
        if (!value) throw new AssertionError("check " + checks);
    }
    private static final class Probe {
        final List<Boolean> published = new ArrayList<>();
        final KeyboardSurfaceSessionState state = new KeyboardSurfaceSessionState(published::add);
        boolean allowed() { return published.get(published.size() - 1); }
        void callback(boolean callbackLocked, boolean currentLocked) {
            if (callbackLocked) state.keyguardLockedEdge();
            state.keyguardChanged(currentLocked);
        }
    }
    public static void main(String[] args) throws Exception {
        for (boolean interactiveFirst : new boolean[] {false, true}) {
            Probe p = new Probe(); check(!p.allowed());
            if (interactiveFirst) p.state.initializeInteractivity(true, true);
            else p.state.keyguardReady(true);
            check(!p.allowed());
            if (interactiveFirst) p.state.keyguardReady(true);
            else p.state.initializeInteractivity(true, true);
            check(!p.allowed());
            p.callback(false, false); check(p.allowed());
            check(p.published.equals(Arrays.asList(false, true)));
            p.state.keyguardLockedEdge(); check(!p.allowed());
            p.callback(false, true); check(!p.allowed());
            p.callback(true, false); check(p.allowed());
            p.state.interactiveChanged(true, false); check(!p.allowed());
            p.callback(false, false); check(!p.allowed());
            p.state.initializeInteractivity(true, true); check(!p.allowed());
            p.state.interactiveChanged(true, true); check(p.allowed());
            p.state.failed(); check(!p.allowed());
            p.callback(false, false); p.state.keyguardReady(false);
            p.state.initializeInteractivity(true, true); p.state.interactiveChanged(true, true);
            check(!p.allowed());
        }
        for (boolean known : new boolean[] {false, true}) {
            Probe staleSeed = new Probe(); staleSeed.state.keyguardReady(false);
            staleSeed.state.interactiveChanged(known, false);
            staleSeed.state.initializeInteractivity(true, true); check(!staleSeed.allowed());
            staleSeed.state.interactiveChanged(true, true); check(staleSeed.allowed());
            staleSeed.state.interactiveChanged(true, false); check(!staleSeed.allowed());
        }
        Probe unknownSeed = new Probe(); unknownSeed.state.keyguardReady(false);
        unknownSeed.state.initializeInteractivity(false, true); check(!unknownSeed.allowed());
        unknownSeed.state.initializeInteractivity(true, true); check(!unknownSeed.allowed());
        unknownSeed.state.interactiveChanged(true, true); check(unknownSeed.allowed());
        Probe failure = new Probe(); failure.state.failed(); failure.state.keyguardReady(false);
        failure.state.initializeInteractivity(true, true); check(!failure.allowed());
        Probe notReady = new Probe(); notReady.state.keyguardChanged(false);
        notReady.state.initializeInteractivity(true, true); check(!notReady.allowed());
        notReady.state.keyguardReady(false); check(notReady.allowed());
        // The external snapshot begins before a Notifier event, but returns after it.
        for (boolean known : new boolean[] {false, true}) {
            Probe racing = new Probe(); racing.state.keyguardReady(false);
            CountDownLatch readStarted = new CountDownLatch(1), returnRead = new CountDownLatch(1);
            Thread bootstrap = new Thread(() -> {
                readStarted.countDown();
                try { returnRead.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
                racing.state.initializeInteractivity(true, true);
            });
            bootstrap.start(); readStarted.await();
            racing.state.interactiveChanged(known, false); returnRead.countDown(); bootstrap.join();
            check(!racing.allowed());
        }
        System.out.println(checks + " production SessionState startup and lock checks passed");
    }
}
