package com.android.server;
import java.util.HashMap;import java.util.Map;
public final class LocalServices {public static final Map<Class<?>,Object> services=new HashMap<>();public static int gets;public static boolean fail;public static <T>T getService(Class<T> type){gets++;if(fail)throw new LinkageError("service");return type.cast(services.get(type));}}
