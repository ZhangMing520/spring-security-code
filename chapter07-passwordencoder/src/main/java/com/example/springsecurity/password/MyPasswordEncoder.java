package com.example.springsecurity.password;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * @author zhangming
 * @date 2020/8/1 15:59
 * <p>
 * 老系统接入 BCryptPasswordEncoder
 */
@Component
public class MyPasswordEncoder extends BCryptPasswordEncoder {

    /**
     * BCRYPT 密文的正则表达式
     */
    private static Pattern BCRYPT_PATTERN = Pattern.compile("\\A\\$2a?\\$\\d\\d$[./0-9A-Za-z]{53}");

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (!BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
            // 明文存储的
            return rawPassword.equals(encodedPassword);
        }
        return super.matches(rawPassword, encodedPassword);
    }
}
