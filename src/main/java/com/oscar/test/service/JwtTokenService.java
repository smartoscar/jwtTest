package com.oscar.test.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.RSAKey;
import com.oscar.test.exception.JwtInvalidException;
import com.oscar.test.po.PayloadDto;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * Created by zsh on 2022/3/9
 */
public interface JwtTokenService {

    /**
     * 模拟生成用户数据
     */
    PayloadDto getDefaultPayloadDto();

    /**
     * 对称加密-使用HMAC对称加密算法生成token
     */
    String generateTokenByHMAC(String payloadStr, String secret) throws KeyLengthException;

    /**
     * 对称加密-验证令牌
     */
    PayloadDto verifyTokenByHMAC(String token, String secret);

    /**
     * 非对称加密-从类路径下加载jwt.jk
     */
    RSAKey loadJKSByClassPath();

    /**
     * 非对称加密-从类路径下加载jwt.jk
     */
    RSAKey generateRsa() throws NoSuchAlgorithmException;

    /**
     * 非对称加密-使用RSA非对称算法生成token
     */
    String generateTokenByRSA(String payloadStr, RSAKey rsaKey) throws JOSEException;

    /**
     * 非对称加密-根据RSA非对称算法验证token
     */
    PayloadDto verifyTokenByRSA(String token, RSAKey rsaKey) throws ParseException, JOSEException, JwtInvalidException;

    /******************** JWE *******************/

    String jweEncrypt(String payload, RSAPublicKey publicKey) throws JOSEException;

    String jweDecrypt(String token, RSAPrivateKey privateKey) throws ParseException, JOSEException;
}