package com.example.springsecurity;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author zhangming
 * @date 2020/7/31 21:35
 */
@SpringBootApplication
@MapperScan("com.example.springsecurity.mapper")
public class AutoLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(AutoLoginApplication.class, args);
    }

}
