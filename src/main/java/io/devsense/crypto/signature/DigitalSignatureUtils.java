package io.devsense.crypto.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignatureUtils {
    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    // Add methods for digital signature generation and verification
    public static byte[] generateDigitalSignature(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign(); // Placeholder
    }

    public static boolean verifyDigitalSignature(byte[] data, byte[] digitalSignatureToVerify, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(digitalSignatureToVerify); // Placeholder
    }
}
