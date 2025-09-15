package io.devsense.crypto.hash;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilsTest {

    @Test
    void generateRandomSalt() {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);
        System.out.println(HexFormat.of().formatHex(salt));
    }

    @Test
    void createHash()  throws Exception{
        byte[] salt = HashUtils.generateRandomSalt();
        String valueToHash = UUID.randomUUID().toString();
        byte[] hash = HashUtils.createHash(valueToHash.getBytes(), salt);
        assertNotNull(hash);
        System.out.println("Value to hash: " + valueToHash);
        byte[] hash2 = HashUtils.createHash(valueToHash.getBytes(), salt);
        assertNotNull(hash2);
        assertEquals(HexFormat.of().formatHex(hash), HexFormat.of().formatHex(hash2));
    }

    @Test
    void hashPassword() {
    }

    @Test
    void testPasswordRoutine() throws Exception {
        String secretPhrase = "correct me if you think you were never wrong!";
        String passswordHash = HashUtils.hashPassword(secretPhrase);
        assertNotNull(passswordHash);
        System.out.println("Password Hash: " + passswordHash);
        assertTrue(HashUtils.verifyPassword(secretPhrase, passswordHash));
    }
}