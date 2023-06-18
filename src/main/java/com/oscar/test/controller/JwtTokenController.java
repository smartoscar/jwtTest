package com.oscar.test.controller;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.json.JSONUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.oscar.test.exception.JwtInvalidException;
import com.oscar.test.po.CommonResult;
import com.oscar.test.po.PayloadDto;
import com.oscar.test.service.JwtTokenService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.text.ParseException;

/**
 * Created by zsh on 2022/3/9
 */
@RestController
public class JwtTokenController {

    @Resource
    private JwtTokenService jwtTokenService;

    @GetMapping(value = "/jwt/generate")
    public Object generateTokenByHMAC() throws KeyLengthException {
        PayloadDto payloadDto = jwtTokenService.getDefaultPayloadDto();
        String token = jwtTokenService.generateTokenByHMAC(JSONUtil.toJsonStr(payloadDto), SecureUtil.md5("test"));
        return token;
    }

    @GetMapping(value = "/jwt/verify")
    public Object verifyTokenByHMAC(String token) {
        PayloadDto payloadDto = jwtTokenService.verifyTokenByHMAC(token, SecureUtil.md5("test"));
        return payloadDto;
    }

    @GetMapping("/rsa/publicKey")
    public CommonResult getRsaPublicKey() {
        RSAKey key = jwtTokenService.loadJKSByClassPath();
        return CommonResult.success(new JWKSet(key).toJSONObject());
    }

    @GetMapping("/rsa/generate")
    public CommonResult generateTokenByRSA() throws JOSEException {
        PayloadDto payloadDto = jwtTokenService.getDefaultPayloadDto();
        RSAKey rsaKey = jwtTokenService.loadJKSByClassPath();
        String token = jwtTokenService.generateTokenByRSA(payloadDto.toString(), rsaKey);
        return CommonResult.success(token);
    }

    @GetMapping("/rsa/verify")
    public CommonResult verifyTokenByRSA(String token) throws ParseException, JOSEException, JwtInvalidException {
        PayloadDto payloadDto = jwtTokenService.verifyTokenByRSA(token, jwtTokenService.loadJKSByClassPath());
        return CommonResult.success(payloadDto);
    }

    @GetMapping("/jwe/encrypt")
    public CommonResult jweEncrypt() throws ParseException, JOSEException, JwtInvalidException {
        PayloadDto payloadDto = jwtTokenService.getDefaultPayloadDto();
        RSAKey rsaKey = jwtTokenService.loadJKSByClassPath();
        String token = jwtTokenService.jweEncrypt(payloadDto.toString(), rsaKey.toRSAPublicKey());
        return CommonResult.success(token);
    }

    @GetMapping("/jwe/decrypt")
    public CommonResult jweDecrypt(String token) throws ParseException, JOSEException, JwtInvalidException {
        RSAKey rsaKey = jwtTokenService.loadJKSByClassPath();
        String payload = jwtTokenService.jweDecrypt(token, rsaKey.toRSAPrivateKey());
        return CommonResult.success(payload);
    }

}