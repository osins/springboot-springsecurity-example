# Springboot-springsecurity-example
对于初次接触springboot的程序员，可能对于Springboot的安全验证比较陌生，本示例希望能够帮助各位快速掌握Spring security的配置和相关代码的编写。
Springboot-springsecurity-example 是一个springboot中应用springsecurity的例子，同时本示例自定义了用户名、密码、验证码的登录验证规则。

### Spring security重要的几个代码在security目录下，其中代码编写顺序如下：
#### 1、用户信息
创建一个继承自org.springframework.security.core.userdetails.UserDetails的类，该类实现了用户基本信息和登录验证相关的几个方法。

SUserDetails继承自UserInfo是Java数据库开源框架Jooq连接数据库自动生成的pojo，即User表对应的Java对象。

```
import com.siyuo2o.glass.db.album.tables.pojos.UserInfo;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class SUserDetails extends UserInfo implements org.springframework.security.core.userdetails.UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

#### 2、数据连接
创建一个继承自org.springframework.security.core.userdetails.UserDetailsService的类，实现数据库中获取用户信息的功能代码。

```
import org.jooq.DSLContext;
import org.jooq.Record;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class SUserDetailsServiceImpl implements UserDetailsService {
    private static final Logger log = LoggerFactory.getLogger(SUserDetailsServiceImpl.class);

    @Autowired
    DSLContext dsl;
    
    com.siyuo2o.glass.db.album.tables.UserInfo userTable = com.siyuo2o.glass.db.album.tables.UserInfo.USER_INFO.as("u");

    @Override
    public SUserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        // 从数据库中获取用户信息，这里连接数据库和SQL操作用的Jooq框架
        Record result = dsl.select().from(userTable).where(userTable.USERNAME.eq(s)).fetchAny();
        if(result == null){
            return null;
        }

        return result.into(SUserDetails.class);
    }
}
```

#### 3、web数据获取
创建一个继承自org.springframework.security.web.authentication.WebAuthenticationDetails的类，实现web验证相关的验证详情来源。

```
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
```
#### 4、web提交登录数据来源绑定
创建一个继承自org.springframework.security.authentication.AuthenticationDetailsSource的类，实现web验证相关的来源。

```
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class SAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest httpServletRequest) {
        return new SWebAuthenticationDetails(httpServletRequest);
    }
}
```

#### 5、自定义登录逻辑
创建一个继承自org.springframework.security.authentication.AuthenticationProvider的类，实现用户登录验证服务，其中authenticate方法是具体验证的方法，其中包括用户名、密码、验证码的比对。
```
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
//        if (SystemUserConstants.STOP.equals(userInfo.getStatus()) ||                     SystemUserConstants.DELETED.equals(userInfo.getStatus())) {
//            throw new DisabledException("账户不可用");
//        }

        Collection<? extends GrantedAuthority> authorities = userInfo.getAuthorities();

        return new UsernamePasswordAuthenticationToken(details.getUsername(), details.getPassword(), authorities);// 构建返回的用户登录成功的token
    }
```

#### 6、配置Spring security
创建一个继承自org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter的类，以实现Spring security的配置。

configure(HttpSecurity http) 方法实现了绑定自定义验证详情来源、登录和成功后的处理规则。
configure(AuthenticationManagerBuilder auth) 方法实现了绑定自定义验证的处理规则。

```
    @Autowired
    private SAuthenticationDetailsSource sAuthenticationDetailsSource;

    @Autowired
    private SUserDetailsServiceImpl userDetailService;

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
                .authenticationDetailsSource(sAuthenticationDetailsSource) //绑定自定义验证详情来源
                .successHandler(securityAuthenticationSuccessHandler)   //板顶自定义登录成功后处理规则
                .failureHandler(securityAuthenticationFailHandler)  //自定义登录失败后的处理规则
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
        auth.authenticationProvider(securityAuthenticationProvider);  //绑定自定义的登录验证规则
    }
```

本例中验证码采用了Google的kaptcha，在DefaultController的login方法中初始化和保存验证码到Session，在继承自AuthenticationProvider的SAuthenticationProvider类中比对用户输入的验证码和session中保存的验证码是否一致。

BCryptPasswordEncoder是Springboot security中自带的一个用户密码加密工具，encode方法用来加密密码，matches方法用来比对用户登录时输入的密码和数据库中获取到的加密后的字符串是否匹配。
