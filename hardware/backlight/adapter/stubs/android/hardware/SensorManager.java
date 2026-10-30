package android.hardware;
import android.os.Handler;
public class SensorManager {public static final int SENSOR_DELAY_NORMAL=3;public Sensor sensor=new Sensor();public SensorEventListener listener;public int registrations,unregistrations;public boolean reject,throwRegister,throwUnregister;
 public Sensor getDefaultSensor(int type){return sensor;}
 public boolean registerListener(SensorEventListener listener,Sensor sensor,int delay,Handler handler){registrations++;if(throwRegister)throw new IllegalStateException("register sensor");if(reject)return false;this.listener=listener;return true;}
 public void unregisterListener(SensorEventListener listener){unregistrations++;if(throwUnregister)throw new IllegalStateException("unregister sensor");if(this.listener==listener)this.listener=null;}
 public void emit(float lux){if(listener!=null)listener.onSensorChanged(new SensorEvent(sensor,lux));}
}
