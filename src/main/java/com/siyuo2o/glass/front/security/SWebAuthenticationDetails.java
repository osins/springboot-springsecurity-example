package com.siyuo2o.glass.front.security;

import com.google.code.kaptcha.Constants;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class SWebAuthenticationDetails extends WebAuthenticationDetails {

    private final String captchCode;
    private final String captchSession;
    private final String username;
    private final String password;

    public SWebAuthenticationDetails(HttpServletRequest request) {
        super(request);

        this.captchCode = request.getParameter(KaptchaConfig.CAPTCHA_CODE_NAME);
        this.captchSession = (String) request.getSession().getAttribute(Constants.KAPTCHA_SESSION_KEY);
        this.username = request.getParameter("username");
        this.password = request.getParameter("password");
    }

    public String getCaptchCode() {
        return captchCode;
    }

    public String getCaptchSession() {
        return captchSession;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
