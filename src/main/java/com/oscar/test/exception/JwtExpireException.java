package com.oscar.test.exception;

public class JwtExpireException extends RuntimeException {
    private Integer code;
    private String msg;

    public JwtExpireException(Integer code, String msg) {
        super(msg);
        this.code = code;
        this.msg = msg;
    }
}
