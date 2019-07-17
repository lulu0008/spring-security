package com.demo.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 登录失败
 */
@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", "10001");
        map.put("msg", exception.getMessage());
        map.put("msg_", "登录验证失败");
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(map));
        writer.flush();
        writer.close();
    }
}
