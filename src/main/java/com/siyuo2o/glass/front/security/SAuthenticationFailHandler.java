package com.siyuo2o.glass.front.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

@Component("securityAuthenticationFailHandler")
public class SAuthenticationFailHandler extends SimpleUrlAuthenticationFailureHandler {
    private Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${security.user.failureUrl}")
    private String failureUrl;// 权限认证失败地址

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        logger.debug("failureUrl:"+failureUrl);
        /** 跳转到指定页面 */
        String redirectUrl = failureUrl+"?message=" + URLEncoder.encode(exception.getMessage(),"UTF-8");
        new DefaultRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}
