package com.android.server.input;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

final class AsyncKeyboardSurfaceSessionPublisher implements Consumer<Boolean> {
    interface Poster {
        boolean post(Runnable task);
    }

    interface NativeSink {
        long stage();
        void publish(boolean allowed, long ticket);
        void blockForever();
    }

    private final Poster mPoster;
    private final NativeSink mNative;
    private final AtomicBoolean mFailed = new AtomicBoolean();

    AsyncKeyboardSurfaceSessionPublisher(Poster poster, NativeSink nativeSink) {
        mPoster = Objects.requireNonNull(poster);
        mNative = Objects.requireNonNull(nativeSink);
    }

    @Override
    public void accept(Boolean allowed) {
        if (mFailed.get()) {
            mNative.blockForever();
            return;
        }
        final boolean value = allowed;
        try {
            final long ticket = mNative.stage();
            if (mPoster.post(() -> {
                if (!mFailed.get()) mNative.publish(value, ticket);
            })) return;
        } catch (RuntimeException unavailable) {
            // A rejected publication permanently blocks the native session.
        }
        failClosed();
    }

    void failClosed() {
        mFailed.set(true);
        mNative.blockForever();
    }
}
