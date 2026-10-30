package com.android.server.input;

final class NativeKeyboardSurfaceSession {
    private static final boolean AVAILABLE;
    private static volatile AsyncKeyboardSurfaceSessionPublisher sPublisher;

    static {
        boolean loaded = false;
        try {
            System.loadLibrary("titan_keyboard_surface");
            loaded = true;
        } catch (LinkageError | SecurityException unavailable) {
            // The native registry starts blocked.
        }
        AVAILABLE = loaded;
    }

    private NativeKeyboardSurfaceSession() {}

    static synchronized void configure(AsyncKeyboardSurfaceSessionPublisher.Poster poster) {
        if (sPublisher != null) {
            sPublisher.failClosed();
            return;
        }
        sPublisher = new AsyncKeyboardSurfaceSessionPublisher(poster,
                new AsyncKeyboardSurfaceSessionPublisher.NativeSink() {
                    @Override public long stage() {
                        return AVAILABLE ? nativeStage() : 0L;
                    }
                    @Override public void publish(boolean allowed, long ticket) {
                        if (AVAILABLE) nativePublish(allowed, ticket);
                    }
                    @Override public void blockForever() {
                        if (AVAILABLE) nativeBlock();
                    }
                });
    }

    static void publish(boolean allowed) {
        final AsyncKeyboardSurfaceSessionPublisher publisher = sPublisher;
        if (publisher != null) {
            publisher.accept(allowed);
        } else if (AVAILABLE) {
            nativeBlock();
        }
    }

    private static native long nativeStage();
    private static native void nativePublish(boolean allowed, long ticket);
    private static native void nativeBlock();
}
