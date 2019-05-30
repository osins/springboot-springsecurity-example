package com.siyuo2o.glass.front.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class SAuthenticationProvider implements AuthenticationProvider {
    private Logger log = LoggerFactory.getLogger(getClass());

    /**
     * 注入我们自己定义的用户信息获取对象
     */
    @Autowired
    private SUserDetailsServiceImpl userDetailService;

    /**
     * 认证用户信息
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SWebAuthenticationDetails details = (SWebAuthenticationDetails) authentication.getDetails();

        log.debug("auth username:"+details.getUsername());
        log.debug("auth password:" + details.getPassword());
        log.debug("auth kaptcha code:"+details.getCaptchCode());
        log.debug("auth kaptcha session:"+ details.getCaptchSession());

        /** 判断用户是否存在 */
        SUserDetails userInfo = userDetailService.loadUserByUsername(details.getUsername()); // 这里调用我们的自己写的获取用户的方法；
        if (userInfo == null) {
            throw new UsernameNotFoundException("用户不存在");
        }

        if (!new BCryptPasswordEncoder().matches(details.getPassword(), userInfo.getPassword())) {
            throw new BadCredentialsException("密码不正确");
        }

        if (!details.getCaptchCode().equals(details.getCaptchSession())) {
            throw new BadCredentialsException("验证码不正确");
        }

        /** 判断账号是否停用/删除 */
//        if (SystemUserConstants.STOP.equals(userInfo.getStatus()) || SystemUserConstants.DELETED.equals(userInfo.getStatus())) {
//            throw new DisabledException("账户不可用");
//        }

        Collection<? extends GrantedAuthority> authorities = userInfo.getAuthorities();

        return new UsernamePasswordAuthenticationToken(details.getUsername(), details.getPassword(), authorities);// 构建返回的用户登录成功的token
    }

    /**
     * 执行支持判断
     *
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return true;// 返回 true ，表示支持执行
    }
}
