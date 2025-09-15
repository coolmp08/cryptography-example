package io.devsense.crypto.keystore;

import javax.crypto.SecretKey;
import java.security.KeyStore;

public class KeyStoreUtils {

    private static final String SECRET_KEY_KEYSTORE_TYPE = "JCEKS";

    public static KeyStore createPrivateJavaKeyStore(String keystorePassword, String keyAlias, SecretKey secretKey, String secretKeyPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(SECRET_KEY_KEYSTORE_TYPE);
        keyStore.load(null, keystorePassword.toCharArray());

        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(secretKeyPassword.toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        keyStore.setEntry(keyAlias, secretKeyEntry, protectionParameter);
        return keyStore;

    }
}
