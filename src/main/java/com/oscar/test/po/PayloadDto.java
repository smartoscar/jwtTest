package com.oscar.test.po;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.List;

@Data
@Builder
@EqualsAndHashCode(callSuper = false)
public class PayloadDto {

    private String sub;

    private Long iat;

    private Long exp;

    private String jti;

    private String username;

    private List<String> authorities;
}