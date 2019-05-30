package com.siyuo2o.glass.front.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.http.HttpServletRequest;

@Component
public class MessageConfig {
    @Autowired
    private HttpServletRequest request;

    @Autowired
    private MessageSource messageSource;

    public String getMessage(String messageKey) {
        //  如果是根据Request请求的语言来决定国际化：
        String message = messageSource.getMessage(messageKey, null, RequestContextUtils.getLocale(request));

        //  如果是根据应用部署的服务器系统来决定国际化：
        //  String message = messageSource.getMessage(messageKey, null, LocaleContextHolder.getLocale());

        return message;
    }
}
