package io.devsense.crypto.keystore;

import io.devsense.crypto.symmetric.SymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import java.security.KeyStore;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreUtilsTest {

    @Test
    void createPrivateKeyJavaKeyStore() throws Exception{
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        String secretKeyHex = HexFormat.of().formatHex(secretKey.getEncoded());

        KeyStore keyStore = KeyStoreUtils.createPrivateJavaKeyStore("keystorePassword", "mySecretKey", secretKey, "secretKeyPassword");
        assertNotNull(keyStore);

        keyStore.load(null, "keystorePassword".toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("secretKeyPassword".toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("mySecretKey", entryPassword);
        SecretKey resultKey = secretKeyEntry.getSecretKey();
        String resultKeyHex = HexFormat.of().formatHex(resultKey.getEncoded());
        assertEquals(secretKeyHex, resultKeyHex);
    }

}