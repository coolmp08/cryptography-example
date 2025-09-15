package io.devsense.crypto.hash;

import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.security.SecureRandom;

public class HashUtils {
    private static final String ALGORITHM = "SHA-256";

    public static byte[] generateRandomSalt() {
        // Implementation to generate and return a random salt
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] createHash(byte[] input, byte[] salt) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(input);
        byte[] saltedInput = byteArrayOutputStream.toByteArray();

        // Implementation to create and return a hash of the input using the provided salt
        java.security.MessageDigest messageDigest = java.security.MessageDigest.getInstance(ALGORITHM);
//        messageDigest.update(salt);
        return messageDigest.digest(saltedInput);
    }

    public static String hashPassword(String password) throws Exception{
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String password, String hashed) throws Exception{
        return BCrypt.checkpw(password, hashed);
    }
}
