package org.example.security;

import java.sql.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnerableCode {
    
    // 漏洞1：直接字符串拼接 SQL 注入
    public void vulnerableQuery1(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }
    
    // 漏洞2：使用 PreparedStatement 但仍然字符串拼接
    public void vulnerableQuery2(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        PreparedStatement pstmt = conn.prepareStatement(query);
        ResultSet rs = pstmt.executeQuery();
    }
    
    // 漏洞3：动态构建 SQL 查询
    public void vulnerableQuery3(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        
        String dynamicSql = "SELECT * FROM products WHERE name LIKE '%" + userInput + "%'";
        ResultSet rs = stmt.executeQuery(dynamicSql);
    }
    
    // 安全示例：使用参数化查询
    public void safeQuery(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
    }
    
    // 安全示例：常量拼接（不是用户输入）
    public void safeConstantQuery() throws SQLException {
        String tablePrefix = "app_";
        String sql = "SELECT * FROM " + tablePrefix + "users WHERE status = 'active'";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }
}