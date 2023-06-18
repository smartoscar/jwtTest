package com.oscar.test.service;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONUtil;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.oscar.test.exception.JwtExpireException;
import com.oscar.test.exception.JwtInvalidException;
import com.oscar.test.po.PayloadDto;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

/**
 * Created by zsh on 2022/3/9
 */
@Service
public class JwtTokenServiceImpl implements JwtTokenService {
    @Override
    public String generateTokenByHMAC(String payloadStr, String secret) {
        try {
            //准备JWS-header
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT).build();
            //将负载信息装载到payload
            Payload payload = new Payload(payloadStr);
            //封装header和payload到JWS对象
            JWSObject jwsObject = new JWSObject(jwsHeader, payload);
            //创建HMAC签名器
            JWSSigner jwsSigner = new MACSigner(secret);
            //签名
            jwsObject.sign(jwsSigner);
            return jwsObject.serialize();
        } catch (KeyLengthException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public PayloadDto getDefaultPayloadDto() {
        Date now = new Date();
        Date exp = DateUtil.offsetSecond(now, 60 * 60);
        return PayloadDto.builder()
                .sub("zsh")
                .iat(now.getTime())
                .exp(exp.getTime())
                .jti(UUID.randomUUID().toString())
                .username("zsh")
                .authorities(CollUtil.toList("ADMIN"))
                .build();
    }

    @Override
    public PayloadDto verifyTokenByHMAC(String token, String secret) {
        try {
            JWSObject jwsObject = JWSObject.parse(token);
            //创建HMAC验证器
            JWSVerifier jwsVerifier = new MACVerifier(secret);
            if (!jwsObject.verify(jwsVerifier)) {
                throw new JwtInvalidException(401, "token签名不合法!");
            }
            String payload = jwsObject.getPayload().toString();
            PayloadDto payloadDto = JSONUtil.toBean(payload, PayloadDto.class);
            if (payloadDto.getExp() < new Date().getTime()) {
                throw new JwtExpireException(401, "token已过期!");
            }
            return payloadDto;
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
        } catch (JwtInvalidException e) {
            e.printStackTrace();
        } catch (JwtExpireException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public RSAKey loadJKSByClassPath() {
        //从类路径下加载证书
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "1qazxsw2".toCharArray());
//        KeyPair keyPair = keyStoreKeyFactory.getKeyPair("mytest", "1qazxsw2".toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair("mytest");
        //获取公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //获取私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).build();
    }

    @Override
    public RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        System.out.println("Base64.encode(publicKey.getEncoded()) = " + Base64.encode(publicKey.getEncoded()));
        System.out.println("Base64.encode(privateKey.getEncoded()) = " + Base64.encode(privateKey.getEncoded()));

        return new RSAKey.Builder(publicKey).privateKey(privateKey).build();
    }

    @Override
    public String generateTokenByRSA(String payloadStr, RSAKey rsaKey) throws JOSEException {
        //构建JWS头
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        //构建载荷
        Payload payload = new Payload(payloadStr);
        //将JWS-header和payload封装成JWS对象中
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        //创建签名器
        JWSSigner signer = new RSASSASigner(rsaKey, true);
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    @Override
    public PayloadDto verifyTokenByRSA(String token, RSAKey rsaKey) throws ParseException, JOSEException, JwtInvalidException {
        JWSObject jwsObject = JWSObject.parse(token);
        RSAKey verifyKey = rsaKey.toPublicJWK();
        JWSVerifier verifier = new RSASSAVerifier(verifyKey);
        if (!jwsObject.verify(verifier)) {
            throw new JwtInvalidException(401, "签名不合法!");
        }
        String payload = jwsObject.getPayload().toString();
        String substring = payload.substring(11, payload.length() - 1);
        String[] strings = substring.split(",");
        PayloadDto payloadDto = PayloadDto.builder()
                .sub(strings[0])
                .iat(100L)
                .exp(100L)
                .jti(strings[3])
                .username(strings[4])
                .authorities(CollUtil.toList(strings[5]))
                .build();
        return payloadDto;
    }

    @Override
    public String jweEncrypt(String payload, RSAPublicKey publicKey) throws JOSEException {
        // 创建加密器
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        RSAEncrypter jweEncrypter = new RSAEncrypter(publicKey);

        // 加密JSON数据
        Payload jwePayload = new Payload(payload);
        JWEObject jweObject = new JWEObject(header, jwePayload);
        jweObject.encrypt(jweEncrypter);

        return jweObject.serialize();
    }

    @Override
    public String jweDecrypt(String token, RSAPrivateKey privateKey) throws ParseException, JOSEException {
        // 创建解密器
        JWEDecrypter jweDecrypter = new RSADecrypter(privateKey);

        // 解密JWE字符串
        JWEObject jweObject = JWEObject.parse(token);
        jweObject.decrypt(jweDecrypter);

        // 解密后的JSON数据转换未JSONObject对象
        Payload payload = jweObject.getPayload();

        return payload.toString();
    }
}