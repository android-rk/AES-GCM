# AES-GCM
Here is the below example of AES-GCm with 128 bit encryption and decryption with Java and Dart/Flutter compatible.

# Java Code

import javax.crypto.Cipher;<br/>
import javax.crypto.KeyGenerator;<br/>
import javax.crypto.SecretKey;<br/>
import javax.crypto.spec.GCMParameterSpec;<br/>
import javax.crypto.spec.SecretKeySpec;<br/>
import java.security.SecureRandom;<br/>
import java.util.Base64;<br/>
class AesGcm {<br/>
   private static final String ALGO = "AES/GCM/NoPadding";
    
    public static String base64IV()
    {
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }
    // Encrypt
    public static String encrypt(String plainText, String secretKey,String ivBase64) throws Exception {
       byte[] iv = Base64.getDecoder().decode(ivBase64);
        Cipher cipher = Cipher.getInstance(ALGO);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        // Return Base64 encoded IV + CipherText
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // Decrypt
    public static String decrypt(String cipherTextEncoded, String secretKey,String ivBase64) throws Exception {
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        byte[] cipherText = Base64.getDecoder().decode(cipherTextEncoded);
        Cipher cipher = Cipher.getInstance(ALGO);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText);
    }
    
	    public static void main(String[] args) throws Exception {
	      String key="testkey123456789";//16 byte any random key or your public key
	      String iv=base64IV();
	      System.out.println("iv="+iv );
	      //encrypting data
	      String plainText="This is a plain text, encrypting it with AES/GCM/NoPadding algo with 12 byte IV";
	      String encryptedText=encrypt(plainText,key,iv);
	      System.out.println("Encrypted Text="+encryptedText );
	      ////decrypting data
	      String decryptedText=decrypt(
	        encryptedText,
	         key,
	         iv);
	      System.out.println("Decrypted Text=" + decryptedText);
	    }
}
# Output
iv=VtnYPGZ6KELIKmqt
Encrypted Text=R4Z7BmHFVQgqrKf0aNpxbGatt5NSyeJRMQJXGEE6KC5Cf4yXxM9NEwwpIq3IYrWq2kVvMLFIXzDYfLcOcbYnSEV3cWxRoGN+TzZZnd29aM2cW6pHmjA7kMIzWpzXTUU=
Decrypted Text=This is a plain text, encrypting it with AES/GCM/NoPadding algo with 12 byte IV


# Dart/Flutter Code (Create a dart class crypto_utl.dart and add below code)

# Decryption in flutter
package used https://pub.dev/packages/encrypt <br/>

import 'dart:convert';<br/>
import 'dart:typed_data';<br/>
import 'package:crypto/crypto.dart';<br/>
import 'package:encrypt/encrypt.dart';<br/>

Uint8List getUint8List(String key) {<br/>
  List<int> keyBytes = utf8.encode(key);<br/>
  var uInt8ListViewOverB = ByteData(16).buffer.asUint8List();<br/>
  uInt8ListViewOverB.setAll(0, keyBytes);<br/>
  return uInt8ListViewOverB;<br/>
}<br/>

String getIvAesGcmBase64() {<br/>
  final iv = IV.fromSecureRandom(12);<br/>
  return iv.base64;<br/>
}<br/>

String encryptAESGCM(<br/>
    {required String plainText,<br/>
    required String encryptionKey,<br/>
    required String base64IV}) {<br/>
  Uint8List key = getUint8List(encryptionKey);<br/>
  final encrypter = Encrypter(AES(Key(key), mode: AESMode.gcm));<br/>
  final encrypted = encrypter.encrypt(plainText, iv: IV.fromBase64(base64IV));<br/>
  return encrypted.base64;<br/>
}<br/>

String decryptAESGCM(<br/>
    {required String encryptedText,<br/>
    required String encryptionKey,<br/>
    required String ivBase64}) {<br/>
  Uint8List key = getUint8List(encryptionKey);<br/>
  final encrypter = Encrypter(AES(Key(key), mode: AESMode.gcm));<br/>
  final decrypted = encrypter.decrypt64(encryptedText, iv: IV.fromBase64(ivBase64));<br/>
  return decrypted;<br/>
}<br/>

Now use it wherever you want<br/>
String enc = 'R4Z7BmHFVQgqrKf0aNpxbGatt5NSyeJRMQJXGEE6KC5Cf4yXxM9NEwwpIq3IYrWq2kVvMLFIXzDYfLcOcbYnSEV3cWxRoGN+TzZZnd29aM2cW6pHmjA7kMIzWpzXTUU='; <br/>
  String decTExt = decryptAESGCM(encryptedText: enc, encryptionKey: 'testkey123456789, ivBase64: 'VtnYPGZ6KELIKmqt);<br/>
  print(decTExt);<br/>
# Output 
flutter: This is a plain text, encrypting it with AES/GCM/NoPadding algo with 12 byte IV

# Similary we can encrypt in flutter
String iv = getIvAesGcmBase64();<br/>
String text="this is a plain text from flutter";<br/>
String encryptedText= encryptAESGCM(plainText: text, encryptionKey: 'testkey123456789', base64IV: iv);<br/>
now you can share encryptedText and iv in API call.<br/>

Thanks.
