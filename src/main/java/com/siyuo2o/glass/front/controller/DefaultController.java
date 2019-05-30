package com.siyuo2o.glass.front.controller;

import com.siyuo2o.glass.db.album.tables.pojos.UserInfo;
import com.siyuo2o.glass.front.security.KaptchaConfig;
import com.siyuo2o.glass.front.config.MessageConfig;
import com.siyuo2o.glass.front.service.UserInfoServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
@RequestMapping("/")
public class DefaultController {
    private static final Logger log = LoggerFactory.getLogger(DefaultController.class);

    @Autowired
    private MessageConfig messageConfig;

    @Autowired
    UserInfoServiceImpl userService;

    @GetMapping("index")
    public ModelAndView index(HttpServletRequest request, Map<String, Object> map) throws Exception{

        ModelAndView model = new ModelAndView("index");

        return model;
    }

    @RequestMapping("login")
    public ModelAndView login(HttpServletRequest request, Map<String, Object> map) throws Exception{
        log.info("start login:", request);

        String errorMessage = "";
        String shiroLoginFailure = (String) request.getAttribute("shiroLoginFailure");
        if (shiroLoginFailure != null) {
            log.debug("Login auth shiroLoginFailure:" + shiroLoginFailure);
            errorMessage = messageConfig.getMessage(shiroLoginFailure);
        }

        log.debug(request.getParameter(KaptchaConfig.CAPTCHA_CODE_NAME));
        ModelAndView model = new ModelAndView("login");
        model.addObject("errorMessage", errorMessage);
        model.addObject("captcha_code_name", KaptchaConfig.CAPTCHA_CODE_NAME);

        // 此方法不处理登录成功,由shiro进行处理
        return model;
    }

    @RequestMapping("register")
    public ModelAndView register(
            @RequestParam(value = "username",required = false,defaultValue = "") String username,
            @RequestParam(value = "password",required = false,defaultValue = "") String password
    ) throws Exception{

        if(username!=null && !username.isEmpty()) {
            System.out.println(username);

            UserInfo info = new UserInfo();
            info.setUsername(username);
            info.setPassword(password);
            userService.addUser(info);
        }

        String msg = "";
        ModelAndView model = new ModelAndView("register");
        model.addObject("msg", msg);

        return model;
    }
}
