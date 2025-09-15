package io.devsense.crypto.signature;

import io.devsense.crypto.asymmetric.ASymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HexFormat;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

class DigitalSignatureUtilsTest {

    @Test
    void generateDigitalSignature() {
    }

    @Test
    void verifyDigitalSignature() {
    }

    @Test
    void digitalSignatureRoutine() throws Exception {
        //Gather data
        URL url = this.getClass().getClassLoader().getResource("demo.txt");
        Path path = null;
        if (url != null) {
            path = Path.of(url.toURI());
        }
        byte[] input = Files.readAllBytes(Objects.requireNonNull(path));

        //Generate a key pair
        KeyPair keyPair = ASymmetricEncryptionUtils.generateRSAKeyPair();
        assertNotNull(keyPair);

        byte [] signature = DigitalSignatureUtils.generateDigitalSignature(input, keyPair.getPrivate());
        assertNotNull(signature);
        System.out.println("Digital Signature: " + HexFormat.of().formatHex(signature));

        assertTrue(DigitalSignatureUtils.verifyDigitalSignature(input,signature, keyPair.getPublic()));



    }
}