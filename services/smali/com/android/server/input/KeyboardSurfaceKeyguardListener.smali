.class final Lcom/android/server/input/KeyboardSurfaceKeyguardListener;
.super Ljava/lang/Object;
.implements Landroid/app/KeyguardManager$KeyguardLockedStateListener;
.field private final mService:Lcom/android/server/input/InputManagerService;
.method constructor <init>(Lcom/android/server/input/InputManagerService;)V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/android/server/input/KeyboardSurfaceKeyguardListener;->mService:Lcom/android/server/input/InputManagerService;
    return-void
.end method
.method public onKeyguardLockedStateChanged(Z)V
    .registers 3
    iget-object v0, p0, Lcom/android/server/input/KeyboardSurfaceKeyguardListener;->mService:Lcom/android/server/input/InputManagerService;
    invoke-virtual {v0, p1}, Lcom/android/server/input/InputManagerService;->refreshKeyboardSurfaceKeyguard(Z)V
    return-void
.end method
