package com.devsense.io.crypto.asymmetric;

import org.junit.jupiter.api.Test;

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
}