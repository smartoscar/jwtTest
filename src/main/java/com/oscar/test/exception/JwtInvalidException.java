package com.oscar.test.exception;

public class JwtInvalidException extends Throwable{
    private Integer code;
    private String msg;

    public JwtInvalidException(Integer code, String msg) {
        super(msg);
        this.code = code;
        this.msg = msg;
    }
}
