package com.oscar.test;

import cn.hutool.core.net.URLDecoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

public class Test {

    public static String jsonStr = "{\"name\"：\"hello\",\"age\":\"26\"}";

    public static String appKey = "SL20231119";
    public static String appSecret = "huifdsahfuida";

    public static SecretKey generateAESKeyFromString(String keyString) throws NoSuchAlgorithmException {
        // 使用SHA-256哈希算法生成固定长度的字节数组
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(keyString.getBytes(StandardCharsets.UTF_8));

        // 使用字节数组创建SecretKey
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String encrypt(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        SecretKey secretKey = generateAESKeyFromString(appSecret);

        String encrypt = encrypt(appKey + Base64.getEncoder().encodeToString(jsonStr.getBytes(StandardCharsets.UTF_8)), secretKey);
        System.out.println(encrypt);
        String decrypt = decrypt(encrypt, secretKey);
        String originStr = new String(Base64.getDecoder().decode(decrypt.replace(appKey, "")));
        System.out.println(originStr);

    }
}
