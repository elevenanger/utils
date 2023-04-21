package cn.anger.utils.sm;

import org.bouncycastle.crypto.digests.SM3Digest;

import java.nio.charset.StandardCharsets;

/**
 * @author : anger
 * SM3 工具类
 */
public class SM3Util {
    private SM3Util() {}

    /**
     * 使用 sm3 算法计算数据的摘要信息
     * @param data 原始数据
     * @return 摘要信息
     */
    public static String hash(String data) {
        return new String(byteHash(data.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    /**
     * 获取摘要信息字节码
     * @param data 原始数据
     * @return 摘要信息字节码
     */
    private static byte[] byteHash(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }
}
