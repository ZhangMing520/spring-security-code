package com.example.springsecurity;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author zhangming
 * @date 2020/7/31 21:35
 *
 * redis keys  spring:session:*
 */
@SpringBootApplication
@MapperScan("com.example.springsecurity.mapper")
public class SessionClusterApplication {

    public static void main(String[] args) {
        SpringApplication.run(SessionClusterApplication.class, args);
    }

}
