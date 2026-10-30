.method final initializeKeyboardSurfaceSession()V
    .registers 7
    :try_start
    iget-object v0, p0, Lcom/android/server/input/InputManagerService;->mContext:Landroid/content/Context;
    const-class v1, Landroid/app/KeyguardManager;
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/app/KeyguardManager;
    iput-object v0, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceKeyguardManager:Landroid/app/KeyguardManager;
    if-eqz v0, :unavailable
    iget-object v1, p0, Lcom/android/server/input/InputManagerService;->mWindowManagerCallbacks:Lcom/android/server/input/InputManagerService$WindowManagerCallbacks;
    if-eqz v1, :unavailable
    new-instance v1, Lcom/android/server/input/KeyboardSurfaceSessionExecutor;
    iget-object v2, p0, Lcom/android/server/input/InputManagerService;->mHandler:Lcom/android/server/input/InputManagerService$InputManagerHandler;
    iget-object v3, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-direct {v1, v2, v3}, Lcom/android/server/input/KeyboardSurfaceSessionExecutor;-><init>(Landroid/os/Handler;Lcom/android/server/input/KeyboardSurfaceSessionState;)V
    new-instance v2, Lcom/android/server/input/KeyboardSurfaceKeyguardListener;
    invoke-direct {v2, p0}, Lcom/android/server/input/KeyboardSurfaceKeyguardListener;-><init>(Lcom/android/server/input/InputManagerService;)V
    invoke-virtual {v0, v1, v2}, Landroid/app/KeyguardManager;->addKeyguardLockedStateListener(Ljava/util/concurrent/Executor;Landroid/app/KeyguardManager$KeyguardLockedStateListener;)V
    iget-object v0, p0, Lcom/android/server/input/InputManagerService;->mWindowManagerCallbacks:Lcom/android/server/input/InputManagerService$WindowManagerCallbacks;
    const/4 v1, 0x0
    invoke-interface {v0, v1}, Lcom/android/server/input/InputManagerService$WindowManagerCallbacks;->isKeyguardLocked(I)Z
    move-result v0
    iget-object v1, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-virtual {v1, v0}, Lcom/android/server/input/KeyboardSurfaceSessionState;->keyguardReady(Z)V
    iget-object v0, p0, Lcom/android/server/input/InputManagerService;->mContext:Landroid/content/Context;
    const-class v1, Landroid/os/PowerManager;
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/os/PowerManager;
    if-eqz v0, :unavailable
    const/4 v1, 0x0
    invoke-virtual {v0, v1}, Landroid/os/PowerManager;->isInteractive(I)Z
    move-result v0
    iget-object v1, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    const/4 v2, 0x1
    invoke-virtual {v1, v2, v0}, Lcom/android/server/input/KeyboardSurfaceSessionState;->initializeInteractivity(ZZ)V
    goto :done
    :unavailable
    new-instance v0, Ljava/lang/IllegalStateException;
    const-string v1, "Keyboard surface state is unavailable"
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V
    throw v0
    :try_end
    .catch Ljava/lang/RuntimeException; {:try_start .. :try_end} :failed
    :failed
    move-exception v0
    iget-object v1, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-virtual {v1}, Lcom/android/server/input/KeyboardSurfaceSessionState;->failed()V
    const-string v1, "InputManager"
    const-string v2, "Keyboard surface remains blocked: session initialization unavailable"
    invoke-static {v1, v2, v0}, Landroid/util/Slog;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :done
    return-void
.end method

.method final refreshKeyboardSurfaceKeyguard(Z)V
    .registers 5
    if-eqz p1, :read_current
    iget-object v0, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-virtual {v0}, Lcom/android/server/input/KeyboardSurfaceSessionState;->keyguardLockedEdge()V
    :read_current
    :try_start
    iget-object v0, p0, Lcom/android/server/input/InputManagerService;->mWindowManagerCallbacks:Lcom/android/server/input/InputManagerService$WindowManagerCallbacks;
    const/4 v1, 0x0
    invoke-interface {v0, v1}, Lcom/android/server/input/InputManagerService$WindowManagerCallbacks;->isKeyguardLocked(I)Z
    move-result v0
    iget-object v1, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-virtual {v1, v0}, Lcom/android/server/input/KeyboardSurfaceSessionState;->keyguardChanged(Z)V
    :try_end
    .catch Ljava/lang/RuntimeException; {:try_start .. :try_end} :failed
    return-void
    :failed
    move-exception v0
    iget-object v1, p0, Lcom/android/server/input/InputManagerService;->mKeyboardSurfaceSession:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-virtual {v1}, Lcom/android/server/input/KeyboardSurfaceSessionState;->failed()V
    const-string v1, "InputManager"
    const-string v2, "Keyboard surface blocked: keyguard state unavailable"
    invoke-static {v1, v2, v0}, Landroid/util/Slog;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    return-void
.end method
