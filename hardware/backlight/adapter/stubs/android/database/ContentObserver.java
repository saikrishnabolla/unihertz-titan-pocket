package android.database;
import android.os.Handler;import android.net.Uri;
public abstract class ContentObserver { public ContentObserver(Handler handler){} public void onChange(boolean selfChange){} public void onChange(boolean selfChange,Uri uri){onChange(selfChange);} }
