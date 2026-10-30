package com.android.server.input;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Executes extracted refresh opcodes; Android stores are independently controlled fakes. */
public final class KeyguardRegression {
    static final class Store {
        boolean locked = true, throwsOnRead;
        int reads;
        boolean read() {
            ++reads;
            if (throwsOnRead) throw new IllegalStateException("source unavailable");
            return locked;
        }
    }
    static final class Machine {
        final Store atms = new Store(), policy = new Store();
        final List<Boolean> values = new ArrayList<>();
        final KeyboardSurfaceSessionState state = new KeyboardSurfaceSessionState(values::add);
        final List<String> code;
        boolean managerMissing;
        Machine(List<String> code) { this.code = code; }
        boolean allowed() { return values.get(values.size() - 1); }
        void ready(boolean locked) { state.keyguardReady(locked); state.initializeInteractivity(true, true); }
        void execute(boolean edge) { execute(code, edge); }
        void execute(List<String> program, boolean edge) {
            List<String> code = program;
            Map<String,Object> r = new HashMap<>(); r.put("p1",edge);
            Map<String,Integer> labels = new HashMap<>();
            for (int i=0;i<code.size();++i) if(code.get(i).startsWith(":")) labels.put(code.get(i),i);
            Object result=null; RuntimeException exception=null;
            int pc=0,steps=0;
            while (pc<code.size()) {
                if (++steps>200) throw new AssertionError("nonterminating input");
                String line=code.get(pc++);
                if(line.isEmpty() || line.startsWith(".") || line.startsWith(":"))continue;
                try {
                    if(line.equals("return-void"))return;
                    if(line.startsWith("iget-object ")) {
                        String dest=line.substring(12,line.indexOf(','));
                        String field=line.substring(line.indexOf("->")+2,line.indexOf(':',line.indexOf("->")));
                        Object value;
                        switch(field) {
                            case "mKeyboardSurfaceSession":value=state;break;
                            case "mWindowManagerCallbacks":value=atms;break;
                            case "mKeyboardSurfaceKeyguardManager":value=policy;break;
                            case "mContext":case "mHandler":value=new Object();break;
                            default:throw new AssertionError("unsupported field "+field);
                        }
                        r.put(dest,value);
                    } else if(line.startsWith("iput-object ") || line.startsWith("check-cast ")) {
                    } else if(line.startsWith("const-class ")) {
                        r.put(line.substring(12,line.indexOf(',')),line.substring(line.indexOf(',')+2));
                    } else if(line.startsWith("if-eqz ")) {
                        String[] parts=line.substring(7).split(", "); Object value=r.get(parts[0]);
                        if(value==null || Boolean.FALSE.equals(value) || Integer.valueOf(0).equals(value))pc=labels.get(parts[1]);
                    } else if(line.startsWith("goto "))pc=labels.get(line.substring(5));
                    else if(line.startsWith("move-result-object "))r.put(line.substring(19),result);
                    else if(line.startsWith("move-result "))r.put(line.substring(12),result);
                    else if(line.startsWith("move-exception "))r.put(line.substring(15),exception);
                    else if(line.startsWith("const/4 ")) {String[] p=line.substring(8).split(", ");r.put(p[0],Integer.decode(p[1]));}
                    else if(line.startsWith("const-string "))r.put(line.substring(13,line.indexOf(',')),"diagnostic");
                    else if(line.startsWith("new-instance "))r.put(line.substring(13,line.indexOf(',')),new IllegalStateException("source unavailable"));
                    else if(line.startsWith("throw "))throw (RuntimeException)r.get(line.substring(6));
                    else if(line.startsWith("invoke-")) {
                        Matcher m=Pattern.compile("\\{([^}]*)\\}, (.*)->([^ (]+)\\(.*").matcher(line);
                        if(!m.find())throw new AssertionError("bad invoke "+line);
                        String[] regs=m.group(1).split(", ");String name=m.group(3);
                        switch(name) {
                            case "getSystemService":result=new Object();break;
                            case "getService":result=managerMissing?null:policy;break;
                            case "isInteractive":result=true;break;
                            case "addKeyguardLockedStateListener":break;
                            case "isKeyguardShowing":
                            case "isKeyguardLocked":result=((Store)r.get(regs[0])).read();break;
                            case "keyguardLockedEdge":state.keyguardLockedEdge();break;
                            case "keyguardChanged":state.keyguardChanged((Boolean)r.get(regs[1]));break;
                            case "keyguardReady":state.keyguardReady((Boolean)r.get(regs[1]));break;
                            case "initializeInteractivity":state.initializeInteractivity(true,(Boolean)r.get(regs[2]));break;
                            case "failed":state.failed();break;
                            case "<init>":case "e":break;
                            default:throw new AssertionError("unsupported invocation "+name);
                        }
                    } else throw new AssertionError("unsupported opcode "+line);
                } catch(RuntimeException failure) {
                    Integer start=labels.get(":try_start"),end=labels.get(":try_end");
                    if(start==null || end==null || pc-1<=start || pc-1>=end
                            || !code.contains(".catch Ljava/lang/RuntimeException; {:try_start .. :try_end} :failed"))throw failure;
                    exception=failure;pc=labels.get(":failed");
                }
            }
            throw new AssertionError("missing return");
        }
    }
    static List<String> method(String text,String name) {
        int start=text.indexOf(".method final "+name); if(start<0)throw new AssertionError("missing method "+name);
        int end=text.indexOf(".end method",start);
        List<String> lines=new ArrayList<>();
        for(String line:text.substring(start,end).split("\\R"))lines.add(line.trim());
        return lines;
    }
    static void require(boolean value,String message) {if(!value)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        String text=new String(Files.readAllBytes(Paths.get(args[0])),java.nio.charset.StandardCharsets.UTF_8);
        List<String> code=method(text,"refreshKeyboardSurfaceKeyguard(Z)V");
        int failed=0;
        for(String scenario:new String[]{"initial-policy-query","initial-null","initial-exception","first-unlock","stale-false-callback","true-edge-must-not-reopen","missing-source","source-exception","failure-stays-closed"}) {
            try {
                Machine m=new Machine(code);m.ready(true);
                switch(scenario) {
                    case "initial-policy-query":
                        m = new Machine(code);m.atms.locked=true;m.policy.locked=false;
                        m.execute(method(text,"initializeKeyboardSurfaceSession()V"),false);
                        require(m.allowed(),"initial snapshot must use current policy source");break;
                    case "initial-null":
                        m = new Machine(code);m.managerMissing=true;m.policy.locked=false;m.atms.locked=false;
                        m.execute(method(text,"initializeKeyboardSurfaceSession()V"),false);
                        require(!m.allowed(),"initial missing policy source must close");break;
                    case "initial-exception":
                        m = new Machine(code);m.policy.throwsOnRead=true;m.atms.locked=false;
                        m.execute(method(text,"initializeKeyboardSurfaceSession()V"),false);
                        require(!m.allowed(),"initial throwing policy source must close");break;
                    case "first-unlock":
                        m.atms.locked=true;m.policy.locked=false;m.execute(false);
                        require(m.allowed(),"first policy unlock must enable despite delayed ATMS store");break;
                    case "stale-false-callback":
                        m.atms.locked=false;m.policy.locked=true;m.execute(false);
                        require(!m.allowed(),"stale false callback must sample current policy lock");break;
                    case "true-edge-must-not-reopen":
                        m.ready(false);m.atms.locked=false;m.policy.locked=false;m.execute(true);
                        require(!m.allowed(),"true edge must not reopen from old unlocked store");
                        require(m.atms.reads==0 && m.policy.reads==0,"true edge must not query");break;
                    case "missing-source":
                        m.ready(false);m.managerMissing=true;m.atms.locked=false;m.execute(false);
                        require(!m.allowed(),"missing source must close");break;
                    case "source-exception":
                        m.ready(false);m.policy.throwsOnRead=true;m.atms.locked=false;m.execute(false);
                        require(!m.allowed(),"source exception must close");break;
                    case "failure-stays-closed":
                        m.ready(false);m.policy.throwsOnRead=true;m.execute(false);
                        m.policy.throwsOnRead=false;m.policy.locked=false;m.atms.locked=false;m.execute(false);
                        require(!m.allowed(),"failed source cannot later reopen");break;
                    default:throw new AssertionError(scenario);
                }
                System.out.println("PASS "+scenario);
            }catch(AssertionError error){++failed;System.out.println("FAIL "+scenario+": "+error.getMessage());}
        }
        System.out.println("failed="+failed);
        if(failed!=0)System.exit(1);
    }
}
