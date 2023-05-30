package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("==================== MyFilter3 Start ====================");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // token을 만들었다고 가정하고 실행
        // token : cos
        /**
         * 로그인시 id, pw가 정상적으로 request가 들어오면
         * token을 생성해주고 해당 token을 response 해준다.
         * 이 후 클라이언트가 request할 떄 마다 header에 Authorization: value(token)을 담아서 request를 보낼 것이다.
         * 그때 받은 token에 대한 검증을 해야 한다.
         */
        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 실패");
            }
        }

        System.out.println("==================== MyFilter3 End ====================");
        chain.doFilter(req, res);
    }
}
