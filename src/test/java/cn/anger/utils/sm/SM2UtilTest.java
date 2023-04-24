package cn.anger.utils.sm;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Anger
 * created on 2023/4/24
 */
class SM2UtilTest {

    static final String PLAIN = "plain text";

    @Test
    void generateKeyPair() {
        assertDoesNotThrow(SM2Util::generateKeyPair);
    }

    @Test
    void getPrivateKeyHexString() {
        AtomicReference<String> privateKey = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            KeyPair pair = SM2Util.generateKeyPair();
            privateKey.set(SM2Util.getPrivateKeyHexString(pair.getPrivate()));
        });
        assertEquals(64, privateKey.get().length());
        System.out.println(privateKey.get());
    }

    @Test
    void getPublicKeyHexString() {
        AtomicReference<String> publicKey = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            KeyPair pair = SM2Util.generateKeyPair();
            publicKey.set(SM2Util.getPublicKeyHexString(pair.getPublic()));
        });
        assertEquals(130, publicKey.get().length());
        System.out.println(publicKey.get());
    }

    @Test
    void encryptAndDecrypt() {
        AtomicReference<String> cipher = new AtomicReference<>();
        AtomicReference<String> decipher = new AtomicReference<>();

        assertDoesNotThrow(() -> {
            KeyPair pair = SM2Util.generateKeyPair();
            String publicKey = SM2Util.getPublicKeyHexString(pair.getPublic());
            String privateKey = SM2Util.getPrivateKeyHexString(pair.getPrivate());

            cipher.set(SM2Util.encrypt(publicKey, PLAIN));
            decipher.set(SM2Util.decrypt(privateKey, cipher.get()));
        });

        assertEquals(PLAIN, decipher.get());

        System.out.println(cipher.get());
    }

    @Test
    void signAndVerify() {
        AtomicReference<String> signature = new AtomicReference<>();
        AtomicBoolean verifyResult = new AtomicBoolean();

        assertDoesNotThrow(() -> {
            KeyPair pair = SM2Util.generateKeyPair();
            String publicKey = SM2Util.getPublicKeyHexString(pair.getPublic());
            String privateKey = SM2Util.getPrivateKeyHexString(pair.getPrivate());

            signature.set(SM2Util.sign(privateKey, PLAIN));
            verifyResult.set(SM2Util.verify(publicKey, PLAIN, signature.get()));
        });

        assertTrue(verifyResult.get());

        System.out.println(signature.get());
    }

}