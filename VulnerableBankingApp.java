// ============================================================
// VulnerableBankingApp.java
// CodeAlpha Internship — Task 3: Secure Coding Review
// PURPOSE: Intentionally vulnerable Java banking application
//          for security analysis and demonstration.
// ⚠️ DO NOT USE IN PRODUCTION — FOR EDUCATIONAL USE ONLY
// ============================================================

import java.sql.*;
import java.util.*;
import java.io.*;
import java.security.MessageDigest;

public class VulnerableBankingApp {

    // ─────────────────────────────────────────────
    // VULNERABILITY 1: Hardcoded Credentials
    // Severity: CRITICAL
    // ─────────────────────────────────────────────
    static final String DB_URL      = "jdbc:mysql://localhost:3306/bankdb";
    static final String DB_USER     = "root";
    static final String DB_PASSWORD = "admin123";  // ⚠️ Hardcoded password

    static final String ADMIN_USER  = "admin";
    static final String ADMIN_PASS  = "password";  // ⚠️ Hardcoded admin credentials

    // ─────────────────────────────────────────────
    // VULNERABILITY 2: SQL Injection
    // Severity: CRITICAL
    // ─────────────────────────────────────────────
    public boolean loginUser(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // ⚠️ VULNERABLE: Direct string concatenation — SQL Injection possible
            String query = "SELECT * FROM users WHERE username='" + username +
                           "' AND password='" + password + "'";

            Statement stmt = conn.createStatement();
            ResultSet rs   = stmt.executeQuery(query);

            // Attacker input: username = "admin'--" bypasses password check
            return rs.next();

        } catch (SQLException e) {
            // ⚠️ VULNERABILITY 3: Sensitive error exposed to user
            System.out.println("Database error: " + e.getMessage());
            return false;
        }
    }

    // ─────────────────────────────────────────────
    // VULNERABILITY 3: Weak Password Hashing (MD5)
    // Severity: HIGH
    // ─────────────────────────────────────────────
    public String hashPassword(String password) {
        try {
            // ⚠️ MD5 is broken — collisions found, rainbow tables exist
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return password; // ⚠️ Returns plain text password on failure!
        }
    }

    // ─────────────────────────────────────────────
    // VULNERABILITY 4: No Input Validation
    // Severity: HIGH
    // ─────────────────────────────────────────────
    public void transferMoney(String fromAccount, String toAccount, double amount) {
        // ⚠️ No validation: negative amounts, zero checks, account format
        // Attacker can transfer negative amount = steal money
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // ⚠️ SQL Injection again — no prepared statements
            String debit  = "UPDATE accounts SET balance = balance - " + amount +
                            " WHERE account_no = '" + fromAccount + "'";
            String credit = "UPDATE accounts SET balance = balance + " + amount +
                            " WHERE account_no = '" + toAccount + "'";

            Statement stmt = conn.createStatement();
            stmt.executeUpdate(debit);
            stmt.executeUpdate(credit);

            // ⚠️ No transaction management — if credit fails, money is lost!

        } catch (SQLException e) {
            System.out.println("Transfer error: " + e.getMessage()); // ⚠️ Info leak
        }
    }

    // ─────────────────────────────────────────────
    // VULNERABILITY 5: Sensitive Data in Logs
    // Severity: HIGH
    // ─────────────────────────────────────────────
    public void logTransaction(String user, String cardNumber, double amount) {
        // ⚠️ Full card number and user data written to plain text log
        System.out.println("LOG: User=" + user +
                           " Card=" + cardNumber +      // ⚠️ Full card number!
                           " Amount=" + amount);

        try {
            FileWriter fw = new FileWriter("transactions.log", true);
            fw.write("User: " + user + " | Card: " + cardNumber + // ⚠️ PII in logs
                     " | Amount: " + amount + "\n");
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // ─────────────────────────────────────────────
    // VULNERABILITY 6: No Session Management
    // Severity: HIGH
    // ─────────────────────────────────────────────
    public String generateSessionToken(String username) {
        // ⚠️ Predictable token — just username + timestamp
        // Easily guessable by attacker
        return username + System.currentTimeMillis();
    }

    // ─────────────────────────────────────────────
    // VULNERABILITY 7: Insecure File Handling
    // Severity: MEDIUM
    // ─────────────────────────────────────────────
    public void downloadStatement(String filename) {
        // ⚠️ Path traversal attack possible
        // Attacker sends: filename = "../../etc/passwd"
        try {
            File file = new File("/statements/" + filename); // ⚠️ No path sanitization
            Scanner sc = new Scanner(file);
            while (sc.hasNextLine()) {
                System.out.println(sc.nextLine());
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────
    // VULNERABILITY 8: No Authorization Check
    // Severity: CRITICAL
    // ─────────────────────────────────────────────
    public void viewAccountDetails(String requestedAccountNo) {
        // ⚠️ No check if logged-in user OWNS this account
        // Any logged-in user can view any account!
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String query = "SELECT * FROM accounts WHERE account_no = '" + requestedAccountNo + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("Account: " + rs.getString("account_no"));
                System.out.println("Balance: " + rs.getDouble("balance"));
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        VulnerableBankingApp app = new VulnerableBankingApp();
        // Test login — vulnerable to SQL injection
        app.loginUser("admin'--", "anything");
        // Negative amount transfer — no validation
        app.transferMoney("ACC001", "ACC002", -5000.0);
        // Log with full card number
        app.logTransaction("john", "4532015112830366", 1000.0);
        // Path traversal
        app.downloadStatement("../../etc/passwd");
    }
}
