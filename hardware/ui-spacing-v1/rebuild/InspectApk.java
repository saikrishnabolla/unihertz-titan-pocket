import java.io.*;import java.nio.file.*;import java.security.*;import java.security.cert.*;import java.util.*;import com.android.apksig.*;
class InspectApk {
 public static void main(String[] args)throws Exception{
  for(String name:args){
   ApkVerifier.Result r=new ApkVerifier.Builder(new File(name)).setMinCheckedPlatformVersion(29).setMaxCheckedPlatformVersion(37).build().verify();
   if(!r.isVerified())throw new Exception("Unverified APK: "+name+" "+r.getErrors());
   System.out.println("APK="+name+" verified="+r.isVerified()+" v2="+r.isVerifiedUsingV2Scheme()+" v3="+r.isVerifiedUsingV3Scheme());
   for(X509Certificate c:r.getSignerCertificates())System.out.println("certificate_sha256="+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()))+" subject="+c.getSubjectX500Principal());
  }
 }
}
