package com.example.springsecurity.provider;

import com.example.springsecurity.exception.VerificationCodeException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author zhangming
 * @date 2020/7/31 22:53
 * <p>
 * 这个图形验证码不完善  因为是 additionalAuthenticationChecks，在此之前会检查“用户是否存在”，
 * 用户和验证码都错误的情况，会优先报错用户不存在
 */
@Component
public class MyAuthenticationProvider extends DaoAuthenticationProvider {

    public MyAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.setUserDetailsService(userDetailsService);
        this.setPasswordEncoder(passwordEncoder);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // 实现图形验证码的逻辑
        MyAuthenticationDetails details = (MyAuthenticationDetails) authentication.getDetails();
        if (!details.isImageCodeIsRight()) {
            throw new VerificationCodeException();
        }

        // 调用父类方法完成密码验证
        super.additionalAuthenticationChecks(userDetails, authentication);
    }

}
