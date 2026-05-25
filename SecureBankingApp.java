// ============================================================
// SecureBankingApp.java
// CodeAlpha Internship — Task 3: Secure Coding Review
// PURPOSE: Fixed, secure version of the banking application
// ============================================================

import java.sql.*;
import java.util.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SecureBankingApp {

    // ─────────────────────────────────────────────
    // FIX 1: No Hardcoded Credentials
    // Load from environment variables instead
    // ─────────────────────────────────────────────
    static final String DB_URL      = System.getenv("DB_URL");
    static final String DB_USER     = System.getenv("DB_USER");
    static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    // Secure logger — no sensitive data
    private static final Logger logger = Logger.getLogger(SecureBankingApp.class.getName());

    // ─────────────────────────────────────────────
    // FIX 2: Prepared Statements (No SQL Injection)
    // ─────────────────────────────────────────────
    public boolean loginUser(String username, String password) {
        if (username == null || password == null ||
            username.isEmpty() || password.isEmpty()) {
            return false;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // ✅ Parameterized query — SQL injection impossible
            String query = "SELECT password_hash, salt FROM users WHERE username = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String storedHash = rs.getString("password_hash");
                String salt       = rs.getString("salt");
                return verifyPassword(password, storedHash, salt);
            }
            return false;

        } catch (SQLException e) {
            // ✅ Generic error — no internal details exposed
            logger.severe("Login error occurred");
            return false;
        }
    }

    // ─────────────────────────────────────────────
    // FIX 3: Strong Password Hashing (PBKDF2)
    // ─────────────────────────────────────────────
    public String hashPassword(String password, String salt) {
        try {
            // ✅ PBKDF2 with HMAC-SHA256 — industry standard
            PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt.getBytes(),
                310000,     // 310,000 iterations
                256         // 256-bit key
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Hashing failed");
        }
    }

    public String generateSalt() {
        // ✅ Cryptographically secure random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public boolean verifyPassword(String inputPassword, String storedHash, String salt) {
        String inputHash = hashPassword(inputPassword, salt);
        return MessageDigest.isEqual(inputHash.getBytes(), storedHash.getBytes());
    }

    // ─────────────────────────────────────────────
    // FIX 4: Input Validation + Transaction Safety
    // ─────────────────────────────────────────────
    public boolean transferMoney(String loggedInUser, String fromAccount,
                                  String toAccount, double amount) {
        // ✅ Validate amount
        if (amount <= 0) {
            logger.warning("Invalid transfer amount: " + amount);
            return false;
        }
        // ✅ Validate account format
        if (!fromAccount.matches("[A-Z0-9]{10}") || !toAccount.matches("[A-Z0-9]{10}")) {
            logger.warning("Invalid account format");
            return false;
        }
        // ✅ Check user owns the fromAccount
        if (!userOwnsAccount(loggedInUser, fromAccount)) {
            logger.warning("Unauthorized transfer attempt by: " + loggedInUser);
            return false;
        }

        Connection conn = null;
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            conn.setAutoCommit(false); // ✅ Transaction management

            // ✅ Check sufficient balance first
            PreparedStatement balCheck = conn.prepareStatement(
                "SELECT balance FROM accounts WHERE account_no = ? FOR UPDATE"
            );
            balCheck.setString(1, fromAccount);
            ResultSet rs = balCheck.executeQuery();
            if (!rs.next() || rs.getDouble("balance") < amount) {
                conn.rollback();
                return false;
            }

            // ✅ Prepared statements — no SQL injection
            PreparedStatement debit = conn.prepareStatement(
                "UPDATE accounts SET balance = balance - ? WHERE account_no = ?"
            );
            debit.setDouble(1, amount);
            debit.setString(2, fromAccount);
            debit.executeUpdate();

            PreparedStatement credit = conn.prepareStatement(
                "UPDATE accounts SET balance = balance + ? WHERE account_no = ?"
            );
            credit.setDouble(1, amount);
            credit.setString(2, toAccount);
            credit.executeUpdate();

            conn.commit(); // ✅ Atomic transaction
            logger.info("Transfer completed successfully");
            return true;

        } catch (SQLException e) {
            try { if (conn != null) conn.rollback(); } catch (SQLException ex) {}
            logger.severe("Transfer failed — rolled back");
            return false;
        } finally {
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }

    // ─────────────────────────────────────────────
    // FIX 5: Safe Logging — No Sensitive Data
    // ─────────────────────────────────────────────
    public void logTransaction(String userId, String cardNumber, double amount) {
        // ✅ Mask card number — show only last 4 digits
        String maskedCard = "****-****-****-" + cardNumber.substring(cardNumber.length() - 4);
        // ✅ Log user ID, not full username/PII
        logger.info("Transaction | UserID=" + userId.hashCode() +
                    " | Card=" + maskedCard +
                    " | Amount=" + amount);
        // ✅ No sensitive data written to file in plain text
    }

    // ─────────────────────────────────────────────
    // FIX 6: Secure Session Token
    // ─────────────────────────────────────────────
    public String generateSessionToken(String username) {
        // ✅ Cryptographically secure random token — unpredictable
        SecureRandom random = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        random.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        // Store token → userId mapping server-side
    }

    // ─────────────────────────────────────────────
    // FIX 7: Safe File Handling (No Path Traversal)
    // ─────────────────────────────────────────────
    public void downloadStatement(String filename, String loggedInUser) {
        try {
            // ✅ Sanitize filename — remove path traversal characters
            String sanitized = filename.replaceAll("[^a-zA-Z0-9._-]", "");

            File base = new File("/statements").getCanonicalFile();
            File file = new File(base, sanitized).getCanonicalFile();

            // ✅ Ensure file is inside allowed directory
            if (!file.getPath().startsWith(base.getPath())) {
                logger.warning("Path traversal attempt by: " + loggedInUser);
                return;
            }

            // ✅ Verify file belongs to logged-in user
            if (!file.getName().startsWith(loggedInUser + "_")) {
                logger.warning("Unauthorized file access attempt");
                return;
            }

            Scanner sc = new Scanner(file);
            while (sc.hasNextLine()) {
                System.out.println(sc.nextLine());
            }
        } catch (IOException e) {
            logger.severe("File access error");
        }
    }

    // ─────────────────────────────────────────────
    // FIX 8: Authorization Check
    // ─────────────────────────────────────────────
    public void viewAccountDetails(String loggedInUser, String requestedAccountNo) {
        // ✅ Always verify ownership before returning data
        if (!userOwnsAccount(loggedInUser, requestedAccountNo)) {
            logger.warning("Unauthorized account access attempt");
            return; // Deny access silently
        }
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT account_no, balance FROM accounts WHERE account_no = ?"
            );
            pstmt.setString(1, requestedAccountNo);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                System.out.println("Account: " + rs.getString("account_no"));
                System.out.println("Balance: " + rs.getDouble("balance"));
            }
        } catch (SQLException e) {
            logger.severe("Account fetch error");
        }
    }

    private boolean userOwnsAccount(String username, String accountNo) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT 1 FROM accounts WHERE account_no = ? AND owner_username = ?"
            );
            pstmt.setString(1, accountNo);
            pstmt.setString(2, username);
            return pstmt.executeQuery().next();
        } catch (SQLException e) {
            return false;
        }
    }
}
