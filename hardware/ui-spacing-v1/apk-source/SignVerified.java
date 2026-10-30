import java.io.*;import java.nio.file.*;import java.security.*;import java.security.cert.*;import java.security.spec.*;import java.util.*;import com.android.apksig.*;
class SignVerified {
 public static void main(String[] a)throws Exception {
  var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(a[0]))));
  X509Certificate cert;try(var in=Files.newInputStream(Path.of(a[1]))){cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);}
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())).equals(a[4]))throw new Exception("Wrong expected certificate");
  var sig=Signature.getInstance("SHA256withRSA");byte[] challenge="Titan controlled native compatibility APK".getBytes();sig.initSign(key);sig.update(challenge);byte[] signed=sig.sign();sig.initVerify(cert);sig.update(challenge);if(!sig.verify(signed))throw new Exception("Key does not match certificate");
  int min=Integer.parseInt(a[5]);var signer=new ApkSigner.SignerConfig.Builder("TITAN",key,List.of(cert)).build();
  new ApkSigner.Builder(List.of(signer)).setInputApk(new File(a[2])).setOutputApk(new File(a[3])).setMinSdkVersion(min).setV1SigningEnabled(false).setV2SigningEnabled(true).setV3SigningEnabled(true).setAlignmentPreserved(false).build().sign();
  for(int api:new int[]{min,30,37}) {if(api<min)continue;var r=new ApkVerifier.Builder(new File(a[3])).setMinCheckedPlatformVersion(api).setMaxCheckedPlatformVersion(api).build().verify();if(!r.isVerified()||r.getSignerCertificates().size()!=1||!Arrays.equals(r.getSignerCertificates().get(0).getEncoded(),cert.getEncoded())||!r.getErrors().isEmpty())throw new Exception("APK verification failed at API"+api);}
  System.out.println("APK signature and expected certificate verified through API37.");
 }
}
