package android.os;
import java.util.ArrayList;import java.util.List;
public class Handler {
 public static final class Entry {public final Runnable task;public final long when;Entry(Runnable task,long when){this.task=task;this.when=when;}}
 public final List<Entry> queue=new ArrayList<>();public final Looper looper=new Looper();public boolean rejectPost,rejectDeadline,throwRemove;public int posts,deadlines,removals;
 public Looper getLooper(){return looper;}
 public boolean post(Runnable task){posts++;if(rejectPost)return false;queue.add(new Entry(task,SystemClock.now));return true;}
 public boolean postAtTime(Runnable task,long when){deadlines++;if(rejectDeadline)return false;queue.add(new Entry(task,when));return true;}
 public void removeCallbacks(Runnable task){removals++;if(throwRemove)throw new IllegalStateException("remove");queue.removeIf(e->e.task==task);}
 public void runUntil(long now){SystemClock.now=now;int guard=0;while(true){Entry found=null;for(Entry e:queue){if(e.when<=now&&(found==null||e.when<found.when))found=e;}if(found==null)return;if(++guard>100)throw new AssertionError("callback loop");queue.remove(found);Looper old=Looper.current;Looper.current=looper;try{found.task.run();}finally{Looper.current=old;}}}
}
