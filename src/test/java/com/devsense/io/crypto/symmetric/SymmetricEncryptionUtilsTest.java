package com.devsense.io.crypto.symmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionUtilsTest {

    @Test
    void createAESKey() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        assertNotNull(secretKey);
        assertEquals("AES", secretKey.getAlgorithm());
//        System.out.println(DatatypeConverter.printHexBinary(secretKey.getEncoded()));
        System.out.println(HexFormat.of().formatHex(secretKey.getEncoded()));
    }

    // Add this test to the SymmetricEncryptionUtilsTest class
    @Test
    void creteInitializationVector() throws Exception {
        byte[] iv = SymmetricEncryptionUtils.creteInitializationVector();
        assertNotNull(iv);
        assertEquals(16, iv.length); // Ensure the IV is 16 bytes long
    }


    @Test
    void testEncryptionDecryptionRoutine() throws Exception{

        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        byte[] iv = SymmetricEncryptionUtils.creteInitializationVector();
        String originalText = "Hello, World from the first cryptography example!";
        byte[] cipherText = SymmetricEncryptionUtils.performAESEncryption(originalText.getBytes(), secretKey, iv);
        assertNotNull(cipherText);
//        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        System.out.println(HexFormat.of().formatHex(cipherText));
        String decryptedText = SymmetricEncryptionUtils.performAESDecryption(cipherText, secretKey, iv);
        assertNotNull(decryptedText);
        assertEquals(originalText, decryptedText);
        System.out.println(HexFormat.of().formatHex(decryptedText.getBytes()));
    }
}