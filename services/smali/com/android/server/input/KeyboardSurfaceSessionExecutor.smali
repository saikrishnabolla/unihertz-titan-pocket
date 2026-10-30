.class final Lcom/android/server/input/KeyboardSurfaceSessionExecutor;
.super Ljava/lang/Object;
.implements Ljava/util/concurrent/Executor;
.field private final mHandler:Landroid/os/Handler;
.field private final mState:Lcom/android/server/input/KeyboardSurfaceSessionState;
.method constructor <init>(Landroid/os/Handler;Lcom/android/server/input/KeyboardSurfaceSessionState;)V
    .registers 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/android/server/input/KeyboardSurfaceSessionExecutor;->mHandler:Landroid/os/Handler;
    iput-object p2, p0, Lcom/android/server/input/KeyboardSurfaceSessionExecutor;->mState:Lcom/android/server/input/KeyboardSurfaceSessionState;
    return-void
.end method
.method public execute(Ljava/lang/Runnable;)V
    .registers 3
    iget-object v0, p0, Lcom/android/server/input/KeyboardSurfaceSessionExecutor;->mHandler:Landroid/os/Handler;
    invoke-virtual {v0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    move-result p1
    if-nez p1, :done
    iget-object v0, p0, Lcom/android/server/input/KeyboardSurfaceSessionExecutor;->mState:Lcom/android/server/input/KeyboardSurfaceSessionState;
    invoke-virtual {v0}, Lcom/android/server/input/KeyboardSurfaceSessionState;->failed()V
    :done
    return-void
.end method
