package cn.anger.utils.sm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * @author : anger
 * sm2 算法相关方法
 */
public class SM2Util {

    private static final X9ECParameters parameters;

    private static final ECDomainParameters domainParameters;

    private static final ECParameterSpec parameterSpec;

    static {
        Security.addProvider(new BouncyCastleProvider());

        // 获取一条 sm2 曲线参数
        parameters = GMNamedCurves.getByName("sm2p256v1");

        // 构造 ecc 算法参数，曲线方程、椭圆曲线G点、大整数N
        domainParameters =
            new ECDomainParameters(
                parameters.getCurve(),
                parameters.getG(),
                parameters.getN());

        parameterSpec =
            new ECParameterSpec(
                parameters.getCurve(),
                parameters.getG(),
                parameters.getN(),
                parameters.getH());
    }

    private SM2Util() {}

    /**
     * 生成国密 sm2 算法秘钥对
     * @return 秘钥对
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec(GMObjectIdentifiers.sm2p256v1.toString());
        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(sm2Spec);

        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 获取16进制字符串格式私钥
     * @param privateKey privateKey 私钥
     * @return 私钥
     */
    public static String getPrivateKeyHexString(PrivateKey privateKey) {
        BCECPrivateKey s = (BCECPrivateKey) privateKey;
        String privateKeyHexString = Hex.toHexString(s.getD().toByteArray());

        if (privateKeyHexString.length() == 66
            && "00".equals(privateKeyHexString.substring(0, 2)))
                privateKeyHexString = privateKeyHexString.substring(2);

        return privateKeyHexString;
    }

    /**
     * 获取16进制字符串格式公钥
     * @param publicKey 公钥
     * @return 公钥
     */
    public static String getPublicKeyHexString(PublicKey publicKey) {
        BCECPublicKey p = (BCECPublicKey) publicKey;
        return Hex.toHexString(p.getQ().getEncoded(false));
    }


    /**
     * sm2 加密算法
     * @param publicKey 公钥
     * @param plainText 数据明文
     * @return 加密后的密文
     */
    public static String encrypt(String publicKey, String plainText) throws InvalidCipherTextException {
        // 获取公钥点
        ECPoint ecPoint = parameters.getCurve().decodePoint(Hex.decode(publicKey));
        ECPublicKeyParameters publicKeyParameters =
            new ECPublicKeyParameters(ecPoint, domainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));

        byte[] in = plainText.getBytes(StandardCharsets.UTF_8);

        return Hex.toHexString(sm2Engine.processBlock(in, 0, in.length));
    }

    public static String decrypt(String privateKey, String cipherText) throws InvalidCipherTextException {
        // 使用 BC 库加解密时密文以 04 开头，传入密文前面没有 04 则加上
        if (!cipherText.startsWith("04"))
            cipherText = "04".concat(cipherText);

        byte[] cipherByte = Hex.decode(cipherText);

        BigInteger privateKeyD = new BigInteger(privateKey, 16);
        ECPrivateKeyParameters privateKeyParameters =
            new ECPrivateKeyParameters(privateKeyD, domainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        // 设置 sm2 为解密模式
        sm2Engine.init(false, privateKeyParameters);

        byte[] arr = sm2Engine.processBlock(cipherByte, 0, cipherByte.length);
        return new String(arr);
    }

    /**
     * 签名
     * @param plainText 需要签名的数据
     * @param privateKey 私钥
     * @return 签名后的数据
     */
    public static String sign(String privateKey, String plainText) throws GeneralSecurityException {
        // 创建签名对象
        Signature signature =
            Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString());
        BigInteger privateKeyD = new BigInteger(privateKey, 16);
        BCECPrivateKey key =
            (BCECPrivateKey) KeyFactory.getInstance("EC")
                                .generatePrivate(new ECPrivateKeySpec(privateKeyD, parameterSpec));
        // 初始化签名状态
        signature.initSign(key);
        // 传入签名的数据
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        // 签名
        return Base64.toBase64String(signature.sign());
    }

    /**
     * 验签
     * @param plainText 明文
     * @param signedData 签名数据
     * @param publicKey 公钥
     * @return 验签结果 true 成功 false 失败
     */
    public static boolean verify(String publicKey, String plainText, String signedData)
        throws GeneralSecurityException {
        Signature signature =
            Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString());
        ECPoint ecPoint = parameters.getCurve().decodePoint(Hex.decode(publicKey));
        BCECPublicKey key =
            (BCECPublicKey) KeyFactory.getInstance("EC")
                                .generatePublic(new ECPublicKeySpec(ecPoint, parameterSpec));
        // 初始化为验签状态
        signature.initVerify(key);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.decode(signedData));
    }

    public static boolean certVerify(String cert, String plainText, String signedData)
        throws GeneralSecurityException {
        byte[] signValue = Base64.decode(signedData);

        CertificateFactory factory = new CertificateFactory();
        X509Certificate certificate =
            (X509Certificate) factory.engineGenerateCertificate(new ByteArrayInputStream(Base64.decode(cert)));

        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initVerify(certificate);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signValue);
    }

}
