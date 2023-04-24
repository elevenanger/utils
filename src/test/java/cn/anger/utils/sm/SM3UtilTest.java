package cn.anger.utils.sm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Anger
 * created on 2023/4/24
 */
class SM3UtilTest {

    static final String PLAIN = "plain text";

    @Test
    void hash() {
        String hash = SM3Util.hash(PLAIN);
        assertEquals(hash, SM3Util.hash(PLAIN));
        System.out.println(hash);
    }

}