package com.android.server.input;

import java.util.function.Consumer;

/** Session gate for the built-in keyboard surface on the default display. */
final class KeyboardSurfaceSessionState {
    private final Consumer<Boolean> mPublish;
    private boolean mListenerReady;
    private boolean mKeyguardKnown;
    private boolean mLocked = true;
    private boolean mInteractiveKnown;
    private boolean mInteractiveObserved;
    private boolean mInteractive;
    private boolean mFailed;
    private boolean mAllowed;

    KeyboardSurfaceSessionState(Consumer<Boolean> publish) {
        mPublish = publish;
        mPublish.accept(false);
    }

    synchronized void keyguardReady(boolean locked) {
        mListenerReady = true;
        mKeyguardKnown = true;
        mLocked = locked;
        publish();
    }

    synchronized void keyguardLockedEdge() {
        mKeyguardKnown = true;
        mLocked = true;
        publish();
    }

    synchronized void keyguardChanged(boolean locked) {
        mKeyguardKnown = true;
        mLocked = locked;
        publish();
    }

    synchronized void initializeInteractivity(boolean known, boolean interactive) {
        // Any Notifier event wins over the initial snapshot, including unknown.
        if (mInteractiveObserved) return;
        mInteractiveObserved = true;
        mInteractiveKnown = known;
        mInteractive = interactive;
        publish();
    }

    synchronized void interactiveChanged(boolean known, boolean interactive) {
        mInteractiveObserved = true;
        mInteractiveKnown = known;
        mInteractive = interactive;
        publish();
    }

    synchronized void failed() {
        mFailed = true;
        publish();
    }

    private void publish() {
        final boolean allowed = !mFailed && mListenerReady && mKeyguardKnown && !mLocked
                && mInteractiveKnown && mInteractive;
        if (allowed != mAllowed) {
            mAllowed = allowed;
            mPublish.accept(allowed);
        }
    }
}
