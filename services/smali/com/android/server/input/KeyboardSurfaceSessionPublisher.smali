.class final Lcom/android/server/input/KeyboardSurfaceSessionPublisher;
.super Ljava/lang/Object;
.implements Ljava/util/function/Consumer;
.method constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public accept(Ljava/lang/Object;)V
    .registers 2
    check-cast p1, Ljava/lang/Boolean;
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z
    move-result p1
    invoke-static {p1}, Lcom/android/server/input/NativeKeyboardSurfaceSession;->publish(Z)V
    return-void
.end method
