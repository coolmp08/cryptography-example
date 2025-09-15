package io.devsense.crypto.asymmetric;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class ASymmetricEncryptionUtils {

    private static final String RSA_ALGORITHM = "RSA";

    // Add methods for encryption and decryption using AES algorithm
    public static KeyPair generateRSAKeyPair() throws Exception {
        // Implementation to create and return an AES SecretKey
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(4096, secureRandom); // Using 2048-bit RSA
        return keyPairGenerator.generateKeyPair(); // Placeholderx
    }

    public static byte[] performRSAEncryption(byte[] plainText, java.security.PrivateKey privateKey) throws Exception {
        Cipher cipher = javax.crypto.Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText);
    }

    public static byte[] performRSADecryption(byte[] cipherText, java.security.PublicKey publicKey) throws Exception {
        Cipher cipher = javax.crypto.Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(cipherText);
    }
}
