package android.content;
import android.database.ContentObserver;import android.net.Uri;import java.util.ArrayList;import java.util.HashMap;import java.util.List;import java.util.Map;
public class ContentResolver {
 public static final class Registration {public final Uri uri;public final ContentObserver observer;Registration(Uri uri,ContentObserver observer){this.uri=uri;this.observer=observer;}}
 public final Map<String,Long> values=new HashMap<>();public final List<Registration> observers=new ArrayList<>();public int registrations,unregistrations,reads;public int failRegistrationAt;public boolean failRead,throwUnregister;
 public void registerContentObserver(Uri uri,boolean descendants,ContentObserver observer){registrations++;if(registrations==failRegistrationAt)throw new SecurityException("register");observers.add(new Registration(uri,observer));}
 public void unregisterContentObserver(ContentObserver observer){unregistrations++;if(throwUnregister)throw new IllegalStateException("unregister");observers.removeIf(r->r.observer==observer);}
 public long read(String key,long fallback){reads++;if(failRead)throw new IllegalStateException("settings");return values.getOrDefault(key,fallback);}
 public void change(String key,long value){values.put(key,value);for(Registration r:new ArrayList<>(observers)){if(r.uri.value.equals(key))r.observer.onChange(false,r.uri);}}
}
