import java.io.*;
import java.util.*;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.android.tools.smali.baksmali.*;
import com.android.tools.smali.smali.*;
public class DexTool {
 public static void main(String[] a) throws Exception {
  if(a[0].equals("disassemble")) {
   DexFile f=DexFileFactory.loadDexFile(new File(a[1]),Opcodes.forDexVersion(39));
   BaksmaliOptions o=new BaksmaliOptions();o.apiLevel=28;
   boolean ok=a.length==3?Baksmali.disassembleDexFile(f,new File(a[2]),1,o):Baksmali.disassembleDexFile(f,new File(a[2]),1,o,Arrays.asList(Arrays.copyOfRange(a,3,a.length)));
   if(!ok)throw new Exception("disassembly failed");
  } else if(a[0].equals("assemble")) {
   SmaliOptions o=new SmaliOptions();o.apiLevel=28;o.jobs=1;o.outputDexFile=a[2];o.verboseErrors=true;
   if(!Smali.assemble(o,a[1]))throw new Exception("assembly failed");
  } else if(a[0].equals("merge")) {
   DexFile f=DexFileFactory.loadDexFile(new File(a[1]),Opcodes.forDexVersion(39));
   DexFile patch=DexFileFactory.loadDexFile(new File(a[2]),Opcodes.forDexVersion(39));
   Map<String,ClassDef> classes=new TreeMap<>();for(ClassDef c:f.getClasses())classes.put(c.getType(),c);
   int old=classes.size();for(ClassDef c:patch.getClasses())classes.put(c.getType(),c);
   DexPool.writeTo(a[3],new ImmutableDexFile(f.getOpcodes(),classes.values()));
   DexFile check=DexFileFactory.loadDexFile(new File(a[3]),Opcodes.forDexVersion(39));
   if(check.getClasses().size()!=classes.size())throw new Exception("class count mismatch");
   System.out.println("originalClasses="+old+" replacementClasses="+patch.getClasses().size()+" resultClasses="+classes.size());
  } else throw new Exception("unknown operation");
 }
}
