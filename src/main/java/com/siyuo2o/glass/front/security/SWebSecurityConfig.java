package com.siyuo2o.glass.front.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SWebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 注入自定义的 验证信息详情来源
     */
    @Autowired
    private SAuthenticationDetailsSource sAuthenticationDetailsSource;

    /**
     * 注入自定义的 AuthenticationProvider (用户名，密码，验证码验证规则）
     */
    @Autowired
    private SAuthenticationProvider securityAuthenticationProvider;

    /**
     * 注入自定义的 AuthenticationSuccessHandler (验证成功的规则）
     */
    @Autowired
    private SAuthenticationSuccessHandler securityAuthenticationSuccessHandler;

    /**
     * 注入自定义的 AuthenticationFailureHandler （验证失败的规则）
     */
    @Autowired
    private SAuthenticationFailHandler securityAuthenticationFailHandler;

    @Autowired
    private SUserDetailsServiceImpl userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .formLogin().loginPage("/login")
            .loginProcessingUrl("/login")
            .authenticationDetailsSource(sAuthenticationDetailsSource)
            .successHandler(securityAuthenticationSuccessHandler)
            .failureHandler(securityAuthenticationFailHandler)
            .permitAll()  // 登录页面链接、登录表单链接、登录失败页面链接配置
            .and()
            .authorizeRequests()
            .antMatchers("/ace/**", "/loginfail", "/kaptcha.jpg").permitAll() // 静态资源配置
            .antMatchers("/index", "/login-error").permitAll() // 免校验链接配置
            .anyRequest().authenticated()
            .and()
            .csrf().disable();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(securityAuthenticationProvider);
    }

    @Override
    public AuthenticationManager authenticationManagerBean() {
        AuthenticationManager authenticationManager = null;
        try {
            authenticationManager = super.authenticationManagerBean();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return authenticationManager;
    }

}