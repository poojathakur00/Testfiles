import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;
import java.util.Scanner;

/**
 * This is a deliberately vulnerable Java application designed to test
 * security scanning tools (SAST).
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
public class VulnerableApp {

    // --- VULNERABILITY 1: Hardcoded Credentials ---
    // Scanners should flag these variables holding sensitive secrets in plain text.
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecretPassword123!"; // FAIL: Hardcoded password
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"; // FAIL: Hardcoded API Key

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("--- Starting Vulnerable Application Test ---");

        try {
            // Simulate getting untrusted input from a user or API
            System.out.print("Enter username to search: ");
            String untrustedInputUser = scanner.nextLine();

            System.out.print("Enter filename to read: ");
            String untrustedInputFile = scanner.nextLine();
            
            System.out.print("Enter password to hash: ");
            String passwordToHash = scanner.nextLine();


            // --- VULNERABILITY 2: SQL Injection ---
            // The user input is directly concatenated into the SQL query string.
            // An attacker could input: ' OR '1'='1
            getUserFromDatabase(untrustedInputUser);

            // --- VULNERABILITY 3: Path Traversal (Local File Inclusion) ---
            // User input is used to construct a file path without validation.
            // An attacker could input: ../../../etc/passwd
            readFileContents(untrustedInputFile);

            // --- VULNERABILITY 4: Command Injection (OS Command Injection) ---
            // User input is part of a string executed by the system shell.
            // An attacker could input: ; rm -rf /
            runSystemCommand(untrustedInputFile);

            // --- VULNERABILITY 5: Weak Cryptography ---
            // Using MD5 or SHA-1 for hashing is insecure as collisions can be found.
            hashPasswordWeakly(passwordToHash);

            // --- VULNERABILITY 6: Insecure Randomness ---
            // Using java.util.Random for generating things like session IDs or tokens is predictable.
            generateSessionTokenInsecurely();


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    /**
     * VULNERABLE METHOD: SQL Injection
     */
    private static void getUserFromDatabase(String username) {
        try {
            Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement statement = connection.createStatement();

            // BAD: Concatenating user input directly into the query
            String sqlQuery = "SELECT * FROM users WHERE username = '" + username + "'";
            System.out.println("Executing Query: " + sqlQuery);

            ResultSet resultSet = statement.executeQuery(sqlQuery);
            while (resultSet.next()) {
                System.out.println("Found user ID: " + resultSet.getInt("id"));
            }
            connection.close();
        } catch (Exception e) {
            System.out.println("Database error (expected if DB not running): " + e.getMessage());
        }
    }

    /**
     * VULNERABLE METHOD: Path Traversal
     */
    private static void readFileContents(String filename) {
        try {
            // BAD: No validation to ensure the path doesn't contain "../"
            // We assume files should only be read from /tmp/public/
            File file = new File("/tmp/public/" + filename);
            
            if (file.exists()) {
                FileInputStream fis = new FileInputStream(file);
                System.out.println("Reading file size: " + fis.available());
                fis.close();
            }
        } catch (IOException e) {
            System.out.println("File IO Error: " + e.getMessage());
        }
    }

    /**
     * VULNERABLE METHOD: Command Injection
     */
    private static void runSystemCommand(String userInput) {
        try {
            // BAD: Concatenating user input directly into a shell command
            String command = "echo 'Processing file: " + userInput + "'";
            
            // Runtime.exec executes the string directly in the OS shell
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            System.out.println("Command executed with exit code: " + exitCode);
        } catch (Exception e) {
            System.out.println("Command execution error: " + e.getMessage());
        }
    }

    /**
     * VULNERABLE METHOD: Weak Hashing Algorithm
     */
    private static void hashPasswordWeakly(String password) {
        try {
            // BAD: MD5 is broken and insecure for password hashing. Use Argon2, bcrypt, or PBKDF2.
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(password.getBytes());
            byte[] digest = md.digest();
            System.out.println("Weak MD5 Hash generated: " + javax.xml.bind.DatatypeConverter.printHexBinary(digest));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * VULNERABLE METHOD: Insecure Random Number Generation
     */
    private static void generateSessionTokenInsecurely() {
        // BAD: java.util.Random is not cryptographically secure.
        // Use java.security.SecureRandom instead for security-sensitive values.
        Random random = new Random();
        int token = random.nextInt(999999);
        System.out.println("Generated insecure session token: " + token);
    }
}
