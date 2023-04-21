package cn.anger.utils.sm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * @author : anger
 * 国密 sm4 算法实现
 */
public class SM4Util {

    private SM4Util() {}

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final String ALGORITHM_NAME = "SM4";

    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";

    public static final int DEFAULT_KEY_SIZE = 128;

    /**
     * 生成默认长度秘钥
     * @return 秘钥（16进制字符串，32位）
     */
    public static String generateKey() throws GeneralSecurityException {
        return Hex.toHexString(generateKey(DEFAULT_KEY_SIZE));
    }

    /**
     * 生成秘钥
     * @param keySize 秘钥长度
     * @return 秘钥字节码
     */
    public static byte[] generateKey(int keySize) throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        generator.init(keySize, new SecureRandom());
        return generator.generateKey().getEncoded();
    }

    /**
     * 生成 ECB 暗号
     * @param mode 模式
     * @param key 秘钥
     * @return 暗号
     */
    private static Cipher generateEcbCipher(int mode, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME_ECB_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    /**
     * 加密
     * @param key 秘钥
     * @param plainText 明文
     * @return 密文
     */
    public static String encrypt(String key, String plainText) throws GeneralSecurityException {
        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);
        byte[] srcData = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] cipherArr = encryptEcbPadding(keyData, srcData);
        return java.util.Arrays.toString(cipherArr);
    }

    /**
     * 加密
     * @param key 秘钥
     * @param data 明文字节码
     * @return 密文字节码
     */
    private static byte[] encryptEcbPadding(byte[] key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = generateEcbCipher(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * 解密
     * @param key 秘钥
     * @param cipherText 密文
     * @return 明文字符串
     */
    public static String decrypt(String key, String cipherText) throws GeneralSecurityException {
        String decryptStr;
        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);
        byte[] cipherData = cipherText.getBytes(StandardCharsets.UTF_8);
        byte[] srcData;
        srcData = decryptEcbPadding(keyData,cipherData);
        decryptStr = new String(srcData, StandardCharsets.UTF_8);
        return decryptStr;
    }

    /**
     * 解密数据
     * @param key 秘钥
     * @param cipherText 密文
     * @return 明文
     */
    private static byte[] decryptEcbPadding(byte[] key, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = generateEcbCipher(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    /**
     * 校验算法加解密后的数据是否一致
     * @param key 秘钥
     * @param cipherText 密文
     * @param plainText 明文
     * @return 比较解密后的密文和明文是否一致
     */
    public static boolean verify(String key, String cipherText, String plainText) throws GeneralSecurityException {
        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);
        byte[] cipherData = cipherText.getBytes(StandardCharsets.UTF_8);
        byte[] decryptData = decryptEcbPadding(keyData, cipherData);
        byte[] srcData = plainText.getBytes(StandardCharsets.UTF_8);
        return Arrays.areEqual(decryptData, srcData);
    }

}