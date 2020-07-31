package com.example.springsecurity.provider;

import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * @author zhangming
 * @date 2020/7/31 23:14
 * <p>
 * 标准的 web 认证源，携带用户的 sessionId Ip 地址
 */
public class MyAuthenticationDetails extends WebAuthenticationDetails {

    private boolean imageCodeIsRight;

    public MyAuthenticationDetails(HttpServletRequest request) {
        super(request);
        String imageCode = request.getParameter("captcha");
        HttpSession session = request.getSession();
        String savedImageCode = (String) session.getAttribute("captcha");
        if (!StringUtils.isEmpty(savedImageCode)) {
            session.removeAttribute("captcha");

            if (!StringUtils.isEmpty(imageCode) && imageCode.equals(savedImageCode)) {
                this.imageCodeIsRight = true;
            }
        }
    }

    public boolean isImageCodeIsRight() {
        return imageCodeIsRight;
    }
}
