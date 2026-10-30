import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import java.lang.reflect.*;
import com.android.apksig.*;

class HelperSignature {
  static String hex(byte[] b) { return HexFormat.of().formatHex(b); }
  static X509Certificate cert(String p) throws Exception {
    try (InputStream in=Files.newInputStream(Path.of(p))) {
      return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
  }
  static void verify(String p, String expected) throws Exception {
    ApkVerifier.Result r=new ApkVerifier.Builder(new File(p))
      .setMinCheckedPlatformVersion(29).setMaxCheckedPlatformVersion(37).build().verify();
    if (!r.isVerified() || !r.isVerifiedUsingV3Scheme())
      throw new Exception("APK v3 verification failed: "+r.getErrors());
    if (r.getSignerCertificates().size()!=1 ||
      !Arrays.equals(r.getSignerCertificates().get(0).getEncoded(),cert(expected).getEncoded()))
      throw new Exception("Signing certificate differs from retained certificate");
    System.out.println("APK v3 verified through API37; certificate SHA256="+
      hex(MessageDigest.getInstance("SHA-256").digest(cert(expected).getEncoded())));
  }
  public static void main(String[] a) throws Exception {
    if (a[0].equals("verify")) { verify(a[1],a[2]); return; }
    if (!a[0].equals("sign")) throw new IllegalArgumentException("verify or sign required");
    PrivateKey key=KeyFactory.getInstance("RSA").generatePrivate(
      new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(a[1]))));
    X509Certificate certificate=cert(a[2]);
    var config=new DefaultApkSignerEngine.SignerConfig.Builder("TITAN",key,List.of(certificate)).build();
    ApkSignerEngine engine=new DefaultApkSignerEngine.Builder(List.of(config),29)
      .setV1SigningEnabled(false).setV2SigningEnabled(false).setV3SigningEnabled(true).build();
    Set<String> retained=Set.of("META-INF/CERT.SF","META-INF/CERT.RSA","META-INF/MANIFEST.MF");
    ApkSignerEngine preserving=(ApkSignerEngine)Proxy.newProxyInstance(
      ApkSignerEngine.class.getClassLoader(),new Class<?>[]{ApkSignerEngine.class},
      (proxy,method,params)->{
        if(method.getName().equals("inputJarEntry") && retained.contains((String)params[0]))
          return new ApkSignerEngine.InputJarEntryInstructions(
            ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT);
        try{return method.invoke(engine,params);}
        catch(InvocationTargetException e){throw e.getCause();}
      });
    new ApkSigner.Builder(preserving).setInputApk(new File(a[3]))
      .setOutputApk(new File(a[4])).setAlignmentPreserved(false).build().sign();
    verify(a[4],a[2]);
  }
}
