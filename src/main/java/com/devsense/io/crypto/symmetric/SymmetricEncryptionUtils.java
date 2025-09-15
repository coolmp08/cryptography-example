package com.devsense.io.crypto.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class SymmetricEncryptionUtils {
    private static final String ALGORITHM = "AES";
    private static final String AEC_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    // Add methods for encryption and decryption using AES algorithm
    public static SecretKey createAESKey() throws Exception {
        // Implementation to create and return an AES SecretKey
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256, secureRandom); // Using 256-bit AES
        return keyGenerator.generateKey(); // Placeholder
    }

    public static byte[] creteInitializationVector() {
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static byte[] performAESEncryption(byte[] plainText, SecretKey secretKey, byte[] iv) throws Exception {
        // Implementation to encrypt the plainText using the provided SecretKey and IV
        Cipher cipher = Cipher.getInstance(AEC_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText); // Placeholder
    }

    public static String performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] iv) throws Exception {
        // Implementation to decrypt the cipherText using the provided SecretKey and IV
        Cipher cipher = Cipher.getInstance(AEC_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes); // Placeholder
    }

}
