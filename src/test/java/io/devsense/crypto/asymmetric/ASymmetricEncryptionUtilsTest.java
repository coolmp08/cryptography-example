package io.devsense.crypto.asymmetric;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class ASymmetricEncryptionUtilsTest {

    @Test
    void generateRSAKeyPair() {
        try {
            var keyPair = ASymmetricEncryptionUtils.generateRSAKeyPair();
            assertNotNull(keyPair);
            assertNotNull(keyPair.getPrivate());
            assertNotNull(keyPair.getPublic());
            assertEquals("RSA", keyPair.getPrivate().getAlgorithm());
            assertEquals("RSA", keyPair.getPublic().getAlgorithm());
            System.out.println("Private Key: " + keyPair.getPrivate());
            System.out.println("Public Key: " + keyPair.getPublic());

            System.out.println("Private Key HEX: " + HexFormat.of().formatHex(keyPair.getPrivate().getEncoded()));
            System.out.println("Public Key HEX: " + HexFormat.of().formatHex(keyPair.getPublic().getEncoded()));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testRSAEncryptionDecryption() throws Exception{
        KeyPair keyPair = ASymmetricEncryptionUtils.generateRSAKeyPair();
        String originalText = "Hello, World from the first asymmetric cryptography example!";
        byte[] cipherText = ASymmetricEncryptionUtils.performRSAEncryption(originalText.getBytes(), keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println(HexFormat.of().formatHex(cipherText));

        byte[] decryptedText = ASymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        assertNotNull(decryptedText);
        assertEquals(originalText, new String(decryptedText));
        System.out.println(HexFormat.of().formatHex(decryptedText));

    }
}