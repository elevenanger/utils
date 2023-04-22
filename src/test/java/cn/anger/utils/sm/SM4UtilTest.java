package cn.anger.utils.sm;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author : anger
 */
class SM4UtilTest {

    static final String KEY = "a9bf686e16420d5ab8fbed00bab88c49";

    static final String PLAIN = "plain text.";

    @Test
    void generateKey() {
        AtomicReference<String> key = new AtomicReference<>();
        assertDoesNotThrow(() -> key.set(SM4Util.generateKey()));
        System.out.println(key.get());
    }

    @Test
    void encrypt() {
        AtomicReference<String> cipher = new AtomicReference<>();
        assertDoesNotThrow(() -> cipher.set(SM4Util.encrypt(KEY, PLAIN)));
        System.out.println(cipher.get());
    }

    @Test
    void decrypt() {
        AtomicReference<String> plain = new AtomicReference<>();

        assertDoesNotThrow(() -> {
            String cipher = SM4Util.encrypt(KEY, PLAIN);
            plain.set(SM4Util.decrypt(KEY, cipher));
        });

        assertEquals(PLAIN, plain.get());
    }

    @Test
    void verify() {
        AtomicBoolean result = new AtomicBoolean(false);
        assertDoesNotThrow(() -> {
            String cipher = SM4Util.encrypt(KEY, PLAIN);
            result.set(SM4Util.verify(KEY, cipher, PLAIN));
        });
        assertTrue(result.get());
    }

}