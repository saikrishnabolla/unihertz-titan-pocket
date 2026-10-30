package android.system;
public final class Os { public static String release="4.14.186-g40b2a1864-dirty";public static boolean fail;public static StructUtsname uname(){if(fail)throw new LinkageError("uname");return new StructUtsname(release);} }
