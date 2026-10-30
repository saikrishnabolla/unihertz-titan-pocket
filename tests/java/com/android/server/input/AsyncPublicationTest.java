package com.android.server.input;

import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;

public final class AsyncPublicationTest {
    static final class Queue implements AsyncKeyboardSurfaceSessionPublisher.Poster {
        final ArrayDeque<Runnable> tasks = new ArrayDeque<>();
        boolean reject, throwsOnPost;
        @Override public boolean post(Runnable task) {
            if (throwsOnPost) throw new IllegalStateException("queue unavailable");
            if (reject) return false;
            tasks.addLast(task);
            return true;
        }
        void drain() { while (!tasks.isEmpty()) tasks.removeFirst().run(); }
    }

    // Atomic model of the coordinator's native stage/commit/permanent-failure ABI.
    static class Sink implements AsyncKeyboardSurfaceSessionPublisher.NativeSink {
        final AtomicLong state = new AtomicLong();
        final AtomicBoolean failed = new AtomicBoolean();
        final List<Long> stages = new CopyOnWriteArrayList<>();
        final List<Boolean> attempted = new CopyOnWriteArrayList<>();
        final List<Boolean> committed = new CopyOnWriteArrayList<>();
        volatile Object callerMonitor = new Object();
        final AtomicInteger blocks = new AtomicInteger();
        @Override public long stage() {
            long previous, next;
            do {
                previous = state.get();
                long generation = previous & ~1L;
                next = generation == ~1L ? ~1L : generation + 2L;
            } while (!state.compareAndSet(previous, next));
            stages.add(next);
            return next;
        }
        @Override public void publish(boolean value, long ticket) {
            if (Thread.holdsLock(callerMonitor)) throw new AssertionError("caller monitor held");
            attempted.add(value);
            if (ticket == 0 || (ticket & 1L) != 0 || Long.compareUnsigned(ticket, ~1L - 2L) >= 0) return;
            long next = (ticket + 2L) | (value && !failed.get() ? 1L : 0L);
            if (state.compareAndSet(ticket, next)) committed.add(value);
        }
        @Override public void blockForever() {
            failed.set(true);
            stage();
            blocks.incrementAndGet();
        }
        boolean allowed() { return (state.get() & 1L) != 0; }
    }

    static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }
    static void await(CountDownLatch latch) {
        try { check(latch.await(5, TimeUnit.SECONDS), "barrier timeout"); }
        catch (InterruptedException e) { throw new AssertionError(e); }
    }

    public static void main(String[] args) throws Exception {
        Queue configured = new Queue();
        NativeKeyboardSurfaceSession.configure(configured);
        NativeKeyboardSurfaceSession.publish(true);
        check(configured.tasks.size() == 1, "configured publish did not enqueue");
        NativeKeyboardSurfaceSession.configure(new Queue());
        NativeKeyboardSurfaceSession.publish(true);
        check(configured.tasks.size() == 1, "repeat configure accepted future publication");
        configured.drain();
        System.out.println("PASS repeated configure permanently disables Java queue");

        Queue q = new Queue(); Sink s = new Sink();
        var p = new AsyncKeyboardSurfaceSessionPublisher(q, s);
        p.accept(true); q.drain();
        check(s.allowed(), "initial true failed");
        long before = s.state.get();
        p.accept(false);
        check(!s.allowed() && s.state.get() > before, "false did not revoke before Handler ran");
        check(s.committed.equals(List.of(true)) && q.tasks.size() == 1, "false commit ran on caller");
        q.drain();
        check(!s.allowed() && s.committed.equals(List.of(true, false)), "false did not commit");
        System.out.println("PASS false immediately blocks while Handler is paused");

        q = new Queue(); s = new Sink(); p = new AsyncKeyboardSurfaceSessionPublisher(q, s);
        p.accept(true); long oldTrue = s.state.get();
        p.accept(false); long newerFalse = s.state.get();
        q.tasks.removeFirst().run();
        check(!s.allowed() && s.state.get() == newerFalse && s.committed.isEmpty(), "stale true reopened");
        q.drain();
        check(s.committed.equals(List.of(false)), "new false did not commit");
        s.publish(true, oldTrue);
        check(!s.allowed(), "consumed old true ticket reopened");
        System.out.println("PASS queued true cannot reopen a newer false stage");

        q = new Queue(); s = new Sink(); p = new AsyncKeyboardSurfaceSessionPublisher(q, s);
        Object callerMonitor = new Object(); s.callerMonitor = callerMonitor;
        synchronized (callerMonitor) {
            p.accept(false); p.accept(true); p.accept(false); p.accept(true);
            check(!s.allowed() && s.stages.equals(List.of(2L, 4L, 6L, 8L)), "stage edges lost");
            check(s.attempted.isEmpty(), "commit ran synchronously");
        }
        q.drain();
        check(s.attempted.equals(List.of(false, true, false, true)), "FIFO attempts lost");
        check(s.committed.equals(List.of(true)) && s.state.get() == 11L, "latest generation not committed");
        s.publish(true, 8L);
        check(s.state.get() == 11L, "ticket reused");
        System.out.println("PASS every false/true stage preserves generation; commit consumes ticket");

        Queue stateQueue = new Queue(); Sink stateSink = new Sink();
        var statePublisher = new AsyncKeyboardSurfaceSessionPublisher(stateQueue, stateSink);
        var state = new KeyboardSurfaceSessionState(statePublisher); stateSink.callerMonitor = state;
        state.keyguardReady(false); state.interactiveChanged(true, true);
        state.keyguardChanged(true); state.keyguardChanged(false);
        check(stateSink.stages.equals(List.of(2L, 4L, 6L, 8L)), "actual state edges lost");
        check(stateSink.attempted.isEmpty() && !stateSink.allowed(), "state commit ran synchronously");
        stateQueue.drain();
        check(stateSink.state.get() == 11L, "actual state latest ticket failed");
        System.out.println("PASS actual SessionState stages under caller monitor and commits after release");

        Queue reentrantQueue = new Queue(); KeyboardSurfaceSessionState[] holder = new KeyboardSurfaceSessionState[1];
        Sink reentrantSink = new Sink() {
            @Override public void publish(boolean value, long ticket) {
                super.publish(value, ticket);
                if (value) {
                    holder[0].keyguardChanged(true);
                    check(!allowed(), "reentrant revocation was delayed");
                }
            }
        };
        var reentrantPublisher = new AsyncKeyboardSurfaceSessionPublisher(reentrantQueue, reentrantSink);
        holder[0] = new KeyboardSurfaceSessionState(reentrantPublisher); reentrantSink.callerMonitor = holder[0];
        holder[0].keyguardReady(false); holder[0].interactiveChanged(true, true);
        reentrantQueue.drain();
        check(reentrantSink.committed.equals(List.of(true, false)) && !reentrantSink.allowed(), "reentry ordering");
        System.out.println("PASS reentrant revocation stages immediately and commits after current callback");

        q = new Queue(); s = new Sink(); p = new AsyncKeyboardSurfaceSessionPublisher(q, s);
        p.accept(true); q.reject = true; p.accept(false);
        check(s.failed.get() && !s.allowed() && s.blocks.get() == 1, "post failure did not block");
        q.reject = false; p.accept(true); q.drain();
        check(s.attempted.isEmpty() && !s.allowed() && s.blocks.get() == 2, "failure allowed queued or new true");
        System.out.println("PASS rejected post invalidates queued true and all future publications");

        q = new Queue(); s = new Sink(); p = new AsyncKeyboardSurfaceSessionPublisher(q, s);
        q.throwsOnPost = true; p.accept(true);
        check(s.failed.get() && !s.allowed(), "post exception did not block");
        System.out.println("PASS post exception permanently blocks");

        q = new Queue(); CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        Sink racing = new Sink() {
            @Override public void publish(boolean value, long ticket) {
                entered.countDown(); await(release); super.publish(value, ticket);
            }
        };
        p = new AsyncKeyboardSurfaceSessionPublisher(q, racing); p.accept(true);
        Thread handler = new Thread(q.tasks.removeFirst(), "test-handler"); handler.start(); await(entered);
        p.accept(false); long stagedFalse = racing.state.get();
        check(!racing.allowed(), "false waited for in-flight commit");
        release.countDown(); handler.join(5000);
        check(!handler.isAlive() && !racing.allowed() && racing.state.get() == stagedFalse, "in-flight stale true reopened");
        q.drain(); check(!racing.allowed(), "false final state wrong");
        System.out.println("PASS already-started true commit loses to newer false stage");

        q = new Queue(); CountDownLatch enteredFailure = new CountDownLatch(1), releaseFailure = new CountDownLatch(1);
        Sink failing = new Sink() {
            @Override public void publish(boolean value, long ticket) {
                enteredFailure.countDown(); await(releaseFailure); super.publish(value, ticket);
            }
        };
        p = new AsyncKeyboardSurfaceSessionPublisher(q, failing); p.accept(true);
        handler = new Thread(q.tasks.removeFirst(), "test-failure-handler"); handler.start(); await(enteredFailure);
        q.reject = true; p.accept(false); check(failing.failed.get() && !failing.allowed(), "failure waited for old commit");
        releaseFailure.countDown(); handler.join(5000);
        check(!handler.isAlive() && !failing.allowed(), "in-flight true reopened permanent failure");
        System.out.println("PASS already-started true commit cannot reopen permanent failure");

        q = new Queue(); s = new Sink(); p = new AsyncKeyboardSurfaceSessionPublisher(q, s);
        p.accept(true); p.failClosed(); p.failClosed(); q.drain(); p.accept(true);
        check(s.blocks.get() == 3 && s.failed.get() && s.attempted.isEmpty() && q.tasks.isEmpty(), "duplicate failure reopened queue");
        System.out.println("PASS every duplicate failure and later accept blocks before returning");

        Queue pausedQueue = new Queue();
        CountDownLatch firstBlockEntered = new CountDownLatch(1), releaseFirstBlock = new CountDownLatch(1);
        AtomicInteger blockCalls = new AtomicInteger();
        Sink pausedFailure = new Sink() {
            @Override public void blockForever() {
                if (blockCalls.incrementAndGet() == 1) {
                    firstBlockEntered.countDown(); await(releaseFirstBlock);
                }
                super.blockForever();
            }
        };
        var pausedPublisher = new AsyncKeyboardSurfaceSessionPublisher(pausedQueue, pausedFailure);
        pausedPublisher.accept(true); pausedQueue.drain();
        check(pausedFailure.allowed(), "paused failure setup not allowed");
        Thread firstFailure = new Thread(pausedPublisher::failClosed, "test-paused-failure-winner");
        firstFailure.start(); await(firstBlockEntered);
        pausedPublisher.failClosed();
        check(!pausedFailure.allowed() && pausedFailure.blocks.get() == 1, "second failure returned before block");
        long afterSecond = pausedFailure.state.get();
        pausedPublisher.accept(true);
        check(!pausedFailure.allowed() && pausedFailure.state.get() > afterSecond,
                "accept on failed publisher returned without its own block");
        releaseFirstBlock.countDown(); firstFailure.join(5000);
        check(!firstFailure.isAlive() && !pausedFailure.allowed() && pausedFailure.blocks.get() == 3,
                "paused failure interleaving reopened state");
        System.out.println("PASS paused first failure cannot let second failure or later accept return allowed");
    }
}
