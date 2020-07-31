package com.example.springsecurity.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author zhangming
 * @date 2020/7/31 22:01
 */
public class VerificationCodeException extends AuthenticationException {

    public VerificationCodeException() {
        super("图形验证码验证失败");
    }
}
