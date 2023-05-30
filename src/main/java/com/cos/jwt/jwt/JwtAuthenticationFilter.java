package com.cos.jwt.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Spring Security에서 UsernamePasswordAuthenticationFilter이 있음
 * "/login" 요청해서 username, password를 request(POST)하면 해당 필터가 동작한다.
 * SecurityConfig에 formLogin을 disable했기 때문에 실행이 안되지만
 * SecurityConfig에 직접 .addFilter(new JwtAuthenticationFilter())로 해당 필터로 등록한다.
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * "/login" 요청 시 로그인 시도를 위해 실행되는 함수
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중");

        /**
         * 1. username, password를 받아서
         * 2. 정상적인 로그인인지 실행하면. authenticationManager로 로그인 시도..?
         * PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행
         * 3. PrincipalDetails를 세션에 담고 (세션에 담는 이유는 권한 관리 때문)
         * 4. jwt 토큰을 만들어서 응답
         */

        return super.attemptAuthentication(request, response);
    }
}
