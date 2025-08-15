package org.example.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class XSSVulnerableCode {
    
    // 漏洞：直接输出用户输入，存在 XSS 风险
    public void vulnerableOutput1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("message");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + userInput + "</h1>");
    }
    
    // 漏洞：在 JavaScript 中直接使用用户输入
    public void vulnerableOutput2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<script>alert('Welcome " + userInput + "!');</script>");
    }
    
    // 安全示例：使用 HTML 编码
    public void safeOutput(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("message");
        String escapedInput = escapeHtml(userInput);
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + escapedInput + "</h1>");
    }
    
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
    }
}