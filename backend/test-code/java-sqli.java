package org.example.security;

import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SQLInjectionVulnerable {
    
    // Vulnerable: String concatenation with executeQuery
    public void vulnerableQuery1(HttpServletRequest request) throws SQLException {
        String userInput = request.getParameter("input");
        String sql = "SELECT * FROM table WHERE column = '" + userInput + "'";
        
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }
    
    // Vulnerable: String concatenation with execute
    public void vulnerableQuery2(String userInput) throws SQLException {
        String sql = "UPDATE users SET status = '" + userInput + "'";
        
        Statement stmt = connection.createStatement();
        stmt.execute(sql);
    }
    
    // Vulnerable: Direct concatenation in executeQuery call
    public void vulnerableQuery3(String userInput) throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.executeQuery("SELECT * FROM products WHERE name = '" + userInput + "'");
    }
    
    // Safe: Using prepared statements
    public void safeQuery(String userInput) throws SQLException {
        String sql = "SELECT * FROM table WHERE column = ?";
        PreparedStatement pstmt = connection.prepareStatement(sql);
        pstmt.setString(1, userInput);
        ResultSet rs = pstmt.executeQuery();
    }
}