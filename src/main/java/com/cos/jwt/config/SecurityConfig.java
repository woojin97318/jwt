package com.cos.jwt.config;

import com.cos.jwt.jwt.JwtAuthenticationFilter;
import com.cos.jwt.jwt.JwtAuthorzationFilter;
import com.cos.jwt.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // Spring Security Filter가 스프링 필터체인에 등록이 된다.
public class SecurityConfig {

    private final CorsConfig corsConfig;

    private final UserRepository userRepository;

    public SecurityConfig(CorsConfig corsConfig, UserRepository userRepository) {
        this.corsConfig = corsConfig;
        this.userRepository = userRepository;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // token을 사용하는 방식이기 때문에 csrf disable
                .csrf().disable()

                /**
                 * 서버는 session 메모리 영역이 존핸다.
                 * 로그인 진행 > 서버는 session id를 response한다.
                 * session id를 받은 클라이언트는 보통 cookie에 해당 값을 저장한다.
                 * 이 후 새로운 resquest가 발생하면 쿠키에 있는 session id를 서버에 같이 보낸다.
                 * 서버별로 세션 영역이 나뉘어져 있기 때문에 해당 방식은 서버가 여러대일 경우 좋지 않다.
                 * 세션을 사용하지 않기 때문에 STATELESS로 설정
                 */
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                .formLogin().disable()
                /** Header에 Authorization을 담고 통신하는 방법 2가지
                 * 1. Basic 방식
                 * id, pw를 담고 request를 보내기 때문에 보안에 취약하다고 한다.
                 * http 방식 -> id, pw 암호화 안된 상태로 통신
                 * https 방식 -> id, pw 암호화 된 상태로 통신
                 * 2. Bearer 방식
                 * id, pw로 생성된 token(jwt)을 담고 request를 보내기에 보안성이 위 방법보다는 좋다고 한다.
                 * 해당 토큰은 노출이 되어도 괜찮다.
                 * 물론 노출이 안되는게 좋다. 해당 토큰을 통해 로그인이 가능하다.
                 * 하지만 토큰의 유효시간이 있기 때문에 안전하다. 위 방법보다는 안전하다고 한다.
                 */
                .httpBasic().disable()
                // 커스텀 필터 등록
                .apply(new MyCustomDsl())

                .and()

                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and().build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

        @Override
        public void configure(HttpSecurity httpSecurity) throws Exception {
            AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);

            httpSecurity
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorzationFilter(authenticationManager, userRepository));
        }
    }
}
