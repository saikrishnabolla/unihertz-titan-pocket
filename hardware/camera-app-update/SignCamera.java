import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import com.android.apksig.*;
class SignCamera {
 public static void main(String[] a)throws Exception{
  var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(a[0]))));
  X509Certificate cert;try(var in=Files.newInputStream(Path.of(a[1]))){cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);}
  String expected="a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc";
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())).equals(expected))throw new Exception("Unexpected certificate");
  byte[] challenge="Titan Camera layout public-development-key match".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(key);signature.update(challenge);byte[] signed=signature.sign();signature.initVerify(cert);signature.update(challenge);if(!signature.verify(signed))throw new Exception("Key/certificate mismatch");
  var signer=new ApkSigner.SignerConfig.Builder("TITANCAMERA",key,List.of(cert)).build();
  new ApkSigner.Builder(List.of(signer)).setInputApk(new File(a[2])).setOutputApk(new File(a[3])).setMinSdkVersion(37).setV1SigningEnabled(false).setV2SigningEnabled(true).setV3SigningEnabled(true).setAlignmentPreserved(false).build().sign();
  var result=new ApkVerifier.Builder(new File(a[3])).setMinCheckedPlatformVersion(37).setMaxCheckedPlatformVersion(37).build().verify();
  if(!result.isVerified()||!result.isVerifiedUsingV3Scheme()||result.getSignerCertificates().size()!=1||!Arrays.equals(result.getSignerCertificates().get(0).getEncoded(),cert.getEncoded())||!result.getErrors().isEmpty())throw new Exception("Candidate signature invalid: "+result.getErrors());
  System.out.println("Signed APK verified at API37; original camera certificate identity retained. Warnings="+result.getWarnings());
 }
}
