.class final Lcom/android/server/input/KeyboardSurfaceSessionPoster;
.super Ljava/lang/Object;
.implements Lcom/android/server/input/AsyncKeyboardSurfaceSessionPublisher$Poster;
.field private final mHandler:Landroid/os/Handler;
.method constructor <init>(Landroid/os/Handler;)V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/android/server/input/KeyboardSurfaceSessionPoster;->mHandler:Landroid/os/Handler;
    return-void
.end method
.method public post(Ljava/lang/Runnable;)Z
    .registers 3
    iget-object v0, p0, Lcom/android/server/input/KeyboardSurfaceSessionPoster;->mHandler:Landroid/os/Handler;
    invoke-virtual {v0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z
    move-result v0
    return v0
.end method
