package com.demo.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 没有权限处理的类
 */
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_FORBIDDEN));
        map.put("msg", e.getMessage());
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        try {
            writer.write(objectMapper.writeValueAsString(map));
            writer.flush();
            writer.close();
        }catch (IOException o){
            o.printStackTrace();
            if(writer != null){
                writer.flush();
                writer.close();
            }
        }
    }
}
