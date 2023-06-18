package com.oscar.test.po;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CommonResult {
    private String code;
    private String msg;
    private Object data;

    public static CommonResult success(Object data) {
        return new CommonResult("0000", "操作成功", data);
    }
}
