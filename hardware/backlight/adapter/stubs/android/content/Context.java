package android.content;
import android.hardware.SensorManager;
public class Context {public static final String SENSOR_SERVICE="sensor";public final ContentResolver resolver=new ContentResolver();public SensorManager sensor=new SensorManager();public int resolverCalls,serviceCalls;public ContentResolver getContentResolver(){resolverCalls++;return resolver;}public Object getSystemService(String name){serviceCalls++;return sensor;}}
