package android.provider;
import android.content.ContentResolver;import android.net.Uri;
public final class Settings {private Settings(){}public static final class Global {private Global(){}public static long getLong(ContentResolver resolver,String key,long fallback){return resolver.read(key,fallback);}public static int getInt(ContentResolver resolver,String key,int fallback){return (int)resolver.read(key,fallback);}public static Uri getUriFor(String key){return new Uri(key);}} }
