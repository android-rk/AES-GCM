# AES-GCM
Here is the below example of AES-GCm with 128 bit encryption and decryption with Java and Dart/Flutter compatible.
# Java Code
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

class AesGcm {
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
package used https://pub.dev/packages/encrypt
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

String encryptAESGCM(String plainText, String base64Key, String base64IV) {
  final encrypter =
      Encrypter(AES(Key(base64Decode(base64Key)), mode: AESMode.gcm));
  final encrypted = encrypter.encrypt(plainText, iv: IV.fromBase64(base64IV));
  return encrypted.base64;
}

String decryptAESGCM(
    String encryptedText, String decryptionKey, String ivBase64) {
  IV iv = IV.fromBase64(ivBase64);
  Uint8List key = getUint8List(decryptionKey);
  final encrypter =
      Encrypter(AES(Key(key), mode: AESMode.gcm, padding: 'NoPadding'));
  final decrypted = encrypter.decrypt64(encryptedText, iv: iv);
  return decrypted;
}

Now use it where you want encryption/decryption
String enc =
      'R4Z7BmHFVQgqrKf0aNpxbGatt5NSyeJRMQJXGEE6KC5Cf4yXxM9NEwwpIq3IYrWq2kVvMLFIXzDYfLcOcbYnSEV3cWxRoGN+TzZZnd29aM2cW6pHmjA7kMIzWpzXTUU=';
  String decTExt = decryptAESGCM(enc, 'testkey123456789', 'VtnYPGZ6KELIKmqt');
  print(decTExt);
  
# Output 
flutter: This is a plain text, encrypting it with AES/GCM/NoPadding algo with 12 byte IV
