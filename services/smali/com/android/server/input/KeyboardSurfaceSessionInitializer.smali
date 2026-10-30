.class final Lcom/android/server/input/KeyboardSurfaceSessionInitializer;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;
.field private final mService:Lcom/android/server/input/InputManagerService;
.method constructor <init>(Lcom/android/server/input/InputManagerService;)V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/android/server/input/KeyboardSurfaceSessionInitializer;->mService:Lcom/android/server/input/InputManagerService;
    return-void
.end method
.method public run()V
    .registers 2
    iget-object v0, p0, Lcom/android/server/input/KeyboardSurfaceSessionInitializer;->mService:Lcom/android/server/input/InputManagerService;
    invoke-virtual {v0}, Lcom/android/server/input/InputManagerService;->initializeKeyboardSurfaceSession()V
    return-void
.end method
