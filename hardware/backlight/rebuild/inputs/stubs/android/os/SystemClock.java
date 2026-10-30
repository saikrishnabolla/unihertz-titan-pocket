package android.os;
public final class SystemClock { public static long now; public static int reads; public static long uptimeMillis(){reads++;return now;} }
