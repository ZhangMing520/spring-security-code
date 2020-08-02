package com.example.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author zhangming
 * @date 2020/8/2 15:31
 */
@RestController
public class SimpleController {

    /**
     * principal 表示当前登录用户
     *
     * @param principal
     * @return
     */
    @GetMapping("/hello")
    public String hello(Principal principal) {
        return "hello, " + principal.getName();
    }

}
