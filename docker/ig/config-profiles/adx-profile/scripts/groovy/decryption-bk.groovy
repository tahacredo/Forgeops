import org.forgerock.security.keystore.KeyStoreManager;
import javax.crypto.Cipher;
import org.forgerock.security.keystore.KeyStoreBuilder;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;

logger.info("in decrypt script!");

def storepassPath = '/app/forgerock/install/ig-config/security/secrets/preprod-storekeypass';
def storepass = new File(storepassPath).getText('UTF-8');
def keystoreType = "JCEKS";
def jceksFilePath = "/app/forgerock/install/ig-config/security/keystores/preprod-keystore.jceks";
def keyAlias = "payloadenckey";
def keyStoreManager;
def privateKey;

def decrypt(value, privateKey) {
    try {
        byte[] decodedBytes = Base64.getDecoder().decode(value);
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        cipher.update(decodedBytes);
        byte[] decrypted = cipher.doFinal();
        return new String(decrypted);
	} catch (Exception e) {
		        logger.info("Value is not base64 encoded: " + value);
		return value;
	}
}

if (request.entity.isRawContentEmpty()) {
    next.handle(context, request);
} else {
    def payload = request.entity.json;
    def passwordCallbacks = payload.callbacks.findAll { it.type == "PasswordCallback" || it.type == "ValidatedCreatePasswordCallback" };
    def nameCallbacks = payload.callbacks.findAll { it.type == "NameCallback" };

    if (passwordCallbacks || nameCallbacks) {
        def builder = new KeyStoreBuilder();
        builder.withKeyStoreFile(jceksFilePath)
                .withKeyStoreType(keystoreType)
                .withPassword(storepass);
        def keystore = builder.build();
        keyStoreManager = new KeyStoreManager(keystore);
        privateKey = keyStoreManager.getPrivateKey(keyAlias, storepass);
    }

    passwordCallbacks.each { callback ->
        def password = callback.input[0].value;
        def decryptedPassword = decrypt(password, privateKey);
        callback.input[0].value = decryptedPassword;
    };

    nameCallbacks.each { callback ->
        def username = callback.input[0].value;
        def decryptedUsername = decrypt(username, privateKey);
        callback.input[0].value = decryptedUsername;
    };

    request.entity.json = payload;
    next.handle(context, request);
}