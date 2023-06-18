package com.oscar.test.po;

public enum AccountRate {

    DDGD(1, "大大股东"),
    DGD(2, "大股东");

    private Integer code;
    private String name;

    AccountRate(Integer code, String name) {
        this.code = code;
        this.name = name;
    }

    public Integer getCode() {
        return code;
    }

    public String getName() {
        return name;
    }
}
