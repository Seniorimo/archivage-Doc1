package com.example.archivage_Doc.Utils;

import org.springframework.web.bind.annotation.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.util.*;
import java.util.zip.ZipInputStream;

// INTENTIONAL VULN - SONARQUBE SAST: Various code vulnerabilities for PFE demo
// This class is not used in business logic, only for SAST testing
public class SonarQubeVulnerabilitiesDemo {

    // VULN 1: Empty catch block (S-108)
    public void emptyCatchBlock() {
        try {
            int result = 10 / 0;
        } catch (Exception e) {
            // Empty catch block - hides errors
        }
    }

    // VULN 2: SQL Injection (S-2077, S-3649)
    public String sqlInjectionVuln(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.toString();
    }

    // VULN 3: SQL Injection with PreparedStatement misuse (S-3649)
    public String sqlInjectionPreparedStatement(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        PreparedStatement pstmt = conn.prepareStatement(query);
        ResultSet rs = pstmt.executeQuery();
        return rs.toString();
    }

    // VULN 4: Hardcoded password (S-2068)
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk_live_1234567890";

    // VULN 5: Weak encryption (S-5542, S-5547)
    public String weakEncryption(String data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }

    // VULN 6: Weak encryption - DES (S-5542)
    public String desEncryption(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // VULN 7: Null pointer dereference (S-2259)
    public String nullPointerDereference(String input) {
        String result = null;
        return result.toUpperCase(); // Potential NPE
    }

    // VULN 8: Path Traversal (S-2083)
    public String pathTraversal(String filename) throws IOException {
        File file = new File("/app/uploads/" + filename);
        return new String(Files.readAllBytes(file.toPath()));
    }

    // VULN 9: Command Injection (S-2083)
    public String commandInjection(String command) throws IOException {
        Process process = Runtime.getRuntime().exec("ls " + command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        return reader.readLine();
    }

    // VULN 10: XXE (S-2755)
    public String xxeVulnerability(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
        return "XML parsed";
    }

    // VULN 11: Unsafe deserialization (S-5042)
    public Object unsafeDeserialization(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // VULN 12: Unreachable code (S-1854)
    public String unreachableCode() {
        return "test";
        return "unreachable"; // This code is never reached
    }

    // VULN 13: Dead code (S-1854)
    public void deadCode() {
        if (false) {
            System.out.println("This code is never executed");
        }
    }

    // VULN 14: Unused variable (S-1481)
    public void unusedVariable() {
        int unused = 10;
        System.out.println("Hello");
    }

    // VULN 15: Empty public constructor (S-1118)
    public SonarQubeVulnerabilitiesDemo() {
        // Empty constructor
    }

    // VULN 16: String literal duplication (S-1192)
    public void stringDuplication() {
        String s1 = "duplicate";
        String s2 = "duplicate";
        String s3 = "duplicate";
    }

    // VULN 17: Cyclomatic complexity (S-3776)
    public int highComplexity(int a, int b, int c, int d, int e) {
        if (a > 0) {
            if (b > 0) {
                if (c > 0) {
                    if (d > 0) {
                        if (e > 0) {
                            return 1;
                        } else {
                            return 2;
                        }
                    } else {
                        return 3;
                    }
                } else {
                    return 4;
                }
            } else {
                return 5;
            }
        } else {
            return 6;
        }
    }

    // VULN 18: Cognitive complexity (S-3776)
    public int cognitiveComplexity(int x) {
        int result = 0;
        if (x > 0) {
            for (int i = 0; i < x; i++) {
                if (i % 2 == 0) {
                    result += i;
                } else {
                    if (i % 3 == 0) {
                        result -= i;
                    } else {
                        result += 1;
                    }
                }
            }
        }
        return result;
    }

    // VULN 19: Method too long (S-138)
    public void veryLongMethod() {
        System.out.println("Line 1");
        System.out.println("Line 2");
        System.out.println("Line 3");
        System.out.println("Line 4");
        System.out.println("Line 5");
        System.out.println("Line 6");
        System.out.println("Line 7");
        System.out.println("Line 8");
        System.out.println("Line 9");
        System.out.println("Line 10");
        System.out.println("Line 11");
        System.out.println("Line 12");
        System.out.println("Line 13");
        System.out.println("Line 14");
        System.out.println("Line 15");
        System.out.println("Line 16");
        System.out.println("Line 17");
        System.out.println("Line 18");
        System.out.println("Line 19");
        System.out.println("Line 20");
        System.out.println("Line 21");
        System.out.println("Line 22");
        System.out.println("Line 23");
        System.out.println("Line 24");
        System.out.println("Line 25");
        System.out.println("Line 26");
        System.out.println("Line 27");
        System.out.println("Line 28");
        System.out.println("Line 29");
        System.out.println("Line 30");
        System.out.println("Line 31");
        System.out.println("Line 32");
        System.out.println("Line 33");
        System.out.println("Line 34");
        System.out.println("Line 35");
        System.out.println("Line 36");
        System.out.println("Line 37");
        System.out.println("Line 38");
        System.out.println("Line 39");
        System.out.println("Line 40");
        System.out.println("Line 41");
        System.out.println("Line 42");
        System.out.println("Line 43");
        System.out.println("Line 44");
        System.out.println("Line 45");
        System.out.println("Line 46");
        System.out.println("Line 47");
        System.out.println("Line 48");
        System.out.println("Line 49");
        System.out.println("Line 50");
    }

    // VULN 20: Too many parameters (S-107)
    public void tooManyParameters(int a, int b, int c, int d, int e, int f, int g, int h) {
        System.out.println(a + b + c + d + e + f + g + h);
    }

    // VULN 21: Nested block depth (S-134)
    public void nestedBlockDepth() {
        if (true) {
            if (true) {
                if (true) {
                    if (true) {
                        if (true) {
                            System.out.println("Deep nesting");
                        }
                    }
                }
            }
        }
    }

    // VULN 22: Switch without default (S-131)
    public int switchWithoutDefault(int value) {
        switch (value) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 3;
        }
        return 0;
    }

    // VULN 23: Conditional always true/false (S-2583, S-2589)
    public void alwaysTrueCondition() {
        boolean flag = true;
        if (flag) {
            System.out.println("Always true");
        }
    }

    // VULN 24: Boolean literal in condition (S-5738)
    public void booleanLiteralCondition() {
        if (true) {
            System.out.println("Always executed");
        }
    }

    // VULN 25: Magic number (S-109)
    public double circleArea(double radius) {
        return 3.14159 * radius * radius;
    }

    // VULN 26: Duplicated code (S-3923)
    public void duplicatedCode1() {
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += i;
        }
        System.out.println(sum);
    }

    public void duplicatedCode2() {
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += i;
        }
        System.out.println(sum);
    }

    // VULN 27: Exception handling with generic Exception (S-1143)
    public void genericException() {
        try {
            int result = 10 / 0;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // VULN 28: Print stack trace (S-1148)
    public void printStackTrace() {
        try {
            int result = 10 / 0;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // VULN 29: System.out or System.err (S-106)
    public void systemOut() {
        System.out.println("Debug output");
        System.err.println("Error output");
    }

    // VULN 30: Thread.sleep in loop (S-2245)
    public void threadSleepInLoop() throws InterruptedException {
        for (int i = 0; i < 10; i++) {
            Thread.sleep(1000);
        }
    }

    // VULN 31: Random object reused (S-2245)
    public void randomReuse() {
        Random random = new Random();
        for (int i = 0; i < 10; i++) {
            System.out.println(random.nextInt());
        }
    }

    // VULN 32: Insecure random (S-2245)
    public int insecureRandom() {
        Random random = new Random();
        return random.nextInt();
    }

    // VULN 33: Weak SSL/TLS (S-4423)
    public void weakSSL() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, null, null);
    }

    // VULN 34: LDAP Injection (S-2077)
    public String ldapInjection(String userInput) throws Exception {
        String query = "(uid=" + userInput + ")";
        return query;
    }

    // VULN 35: OS command injection (S-2083)
    public String osCommandInjection(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        return reader.readLine();
    }

    // VULN 36: XPath Injection (S-2077)
    public String xpathInjection(String userInput) {
        String xpath = "//user[username='" + userInput + "']";
        return xpath;
    }

    // VULN 37: Regular expression denial of service (S-2631)
    public boolean regexDos(String input) {
        return input.matches("(a+)+");
    }

    // VULN 38: Cookie without secure flag (S-5122)
    public void insecureCookie() {
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("session", "value");
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
    }

    // VULN 39: Session fixation (S-5144)
    public void sessionFixation(javax.servlet.http.HttpServletRequest request) {
        request.getSession(true);
    }

    // VULN 40: CSRF protection missing (S-5147)
    @PostMapping("/transfer")
    public String csrfVulnerable(@RequestParam String amount) {
        return "Transferred " + amount;
    }

    // VULN 41: Open redirect (S-5131)
    public String openRedirect(String url) {
        return "redirect:" + url;
    }

    // VULN 42: Information exposure through error message (S-5693)
    public String errorExposure(String input) {
        try {
            int result = Integer.parseInt(input);
            return "Success: " + result;
        } catch (NumberFormatException e) {
            return "Error parsing input: " + input + " - " + e.getMessage();
        }
    }

    // VULN 43: Logging sensitive information (S-2068)
    public void logSensitiveInfo(String password) {
        System.out.println("User password: " + password);
    }

    // VULN 44: File disclosure (S-2083)
    public String fileDisclosure(String filename) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filename)));
    }

    // VULN 45: Zip slip (S-5042)
    public void zipSlip(String zipFile) throws Exception {
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
        java.util.zip.ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File file = new File(entry.getName());
            Files.copy(zis, file.toPath());
        }
    }

    // VULN 46: Weak hash (S-5542)
    public String weakHash(String data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] digest = sha1.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }

    // VULN 47: Hardcoded IP address (S-1313)
    private static final String DB_HOST = "192.168.1.100";

    // VULN 48: Hardcoded port (S-1313)
    private static final int DB_PORT = 3306;

    // VULN 49: Use of non-serializable class (S-1948)
    public class NonSerializable implements Serializable {
        private transient Object obj;
    }

    // VULN 50: compareTo returns Integer (S-1210)
    public int compareToReturnsInteger(Object o) {
        return Integer.compare(0, 0);
    }

    // VULN 51: equals() not overridden (S-2160)
    public class EqualsNotOverridden {
        private int value;
    }

    // VULN 52: hashCode() not overridden (S-2160)
    public class HashCodeNotOverridden {
        private int value;
    }

    // VULN 53: SimpleDateFormat not thread-safe (S-2755)
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");

    // VULN 54: Calendar not thread-safe (S-2755)
    private static final Calendar CALENDAR = Calendar.getInstance();

    // VULN 55: ArrayList not synchronized (S-2245)
    private static final List<String> LIST = new ArrayList<>();

    // VULN 56: HashMap not synchronized (S-2245)
    private static final Map<String, String> MAP = new HashMap<>();

    // VULN 57: HashSet not synchronized (S-2245)
    private static final Set<String> SET = new HashSet<>();

    // VULN 58: StringBuilder not synchronized (S-2245)
    private static final StringBuilder BUILDER = new StringBuilder();

    // VULN 59: StringBuffer should be used instead (S-2245)
    public void stringBuilder() {
        StringBuilder sb = new StringBuilder();
        sb.append("test");
    }

    // VULN 60: Vector should not be used (S-1149)
    public void vectorUsage() {
        Vector<String> vector = new Vector<>();
        vector.add("test");
    }

    // VULN 61: Hashtable should not be used (S-1149)
    public void hashtableUsage() {
        Hashtable<String, String> table = new Hashtable<>();
        table.put("key", "value");
    }

    // VULN 62: Stack should not be used (S-1149)
    public void stackUsage() {
        Stack<String> stack = new Stack<>();
        stack.push("test");
    }

    // VULN 63: Properties should not be used (S-1149)
    public void propertiesUsage() {
        Properties props = new Properties();
        props.setProperty("key", "value");
    }

    // VULN 64: String concatenation in loop (S-1943)
    public void stringConcatenationInLoop() {
        String result = "";
        for (int i = 0; i < 100; i++) {
            result += i;
        }
    }

    // VULN 65: Object creation in loop (S-2245)
    public void objectCreationInLoop() {
        for (int i = 0; i < 100; i++) {
            String s = new String("test");
        }
    }

    // VULN 66: Boxing/unboxing (S-2111)
    public void boxingUnboxing() {
        Integer a = 10;
        int b = a;
    }

    // VULN 67: Autoboxing (S-2111)
    public void autoboxing() {
        List<Integer> list = new ArrayList<>();
        list.add(10);
    }

    // VULN 68: Unboxing (S-2111)
    public void unboxing() {
        Integer a = Integer.valueOf(10);
        int b = a;
    }

    // VULN 69: Character comparison (S-3031)
    public boolean characterComparison(char c) {
        return c == 'a' || c == 'A';
    }

    // VULN 70: String comparison (S-3031)
    public boolean stringComparison(String s) {
        return s == "test";
    }

    // VULN 71: Array comparison (S-3031)
    public boolean arrayComparison(int[] a, int[] b) {
        return a == b;
    }

    // VULN 72: Collection comparison (S-3031)
    public boolean collectionComparison(List<String> a, List<String> b) {
        return a == b;
    }

    // VULN 73: Null check (S-3031)
    public boolean nullCheck(String s) {
        return s != null && s.equals("test");
    }

    // VULN 74: Optional used incorrectly (S-3031)
    public void optionalIncorrect() {
        Optional<String> opt = Optional.of("test");
        if (opt.isPresent()) {
            System.out.println(opt.get());
        }
    }

    // VULN 75: Stream not closed (S-2095)
    public void streamNotClosed() throws Exception {
        Files.lines(Paths.get("test.txt")).forEach(System.out::println);
    }

    // VULN 76: Reader not closed (S-2095)
    public void readerNotClosed() throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader("test.txt"));
        reader.readLine();
    }

    // VULN 77: Writer not closed (S-2095)
    public void writerNotClosed() throws Exception {
        BufferedWriter writer = new BufferedWriter(new FileWriter("test.txt"));
        writer.write("test");
    }

    // VULN 78: InputStream not closed (S-2095)
    public void inputStreamNotClosed() throws Exception {
        InputStream is = new FileInputStream("test.txt");
        is.read();
    }

    // VULN 79: OutputStream not closed (S-2095)
    public void outputStreamNotClosed() throws Exception {
        OutputStream os = new FileOutputStream("test.txt");
        os.write(1);
    }

    // VULN 80: URLConnection not closed (S-2095)
    public void urlConnectionNotClosed() throws Exception {
        URL url = new URL("http://example.com");
        URLConnection conn = url.openConnection();
        conn.getInputStream();
    }

    // VULN 81: Database connection not closed (S-2095)
    public void connectionNotClosed() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT 1");
    }

    // VULN 82: Statement not closed (S-2095)
    public void statementNotClosed() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT 1");
        conn.close();
    }

    // VULN 83: ResultSet not closed (S-2095)
    public void resultSetNotClosed() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT 1");
        conn.close();
    }

    // VULN 84: Finally block without return (S-1141)
    public String finallyWithoutReturn() {
        try {
            return "try";
        } finally {
            return "finally";
        }
    }

    // VULN 85: Return in finally (S-1141)
    public String returnInFinally() {
        try {
            return "try";
        } finally {
            return "finally";
        }
    }

    // VULN 86: Throw in finally (S-1141)
    public void throwInFinally() {
        try {
            System.out.println("try");
        } finally {
            throw new RuntimeException();
        }
    }

    // VULN 87: Catch Exception before specific (S-1186)
    public void catchExceptionFirst() {
        try {
            int result = 10 / 0;
        } catch (Exception e) {
            System.out.println("Exception");
        } catch (ArithmeticException e) {
            System.out.println("ArithmeticException");
        }
    }

    // VULN 88: Catch Throwable (S-1186)
    public void catchThrowable() {
        try {
            int result = 10 / 0;
        } catch (Throwable t) {
            System.out.println("Throwable");
        }
    }

    // VULN 89: Catch Error (S-1186)
    public void catchError() {
        try {
            int result = 10 / 0;
        } catch (Error e) {
            System.out.println("Error");
        }
    }

    // VULN 90: Multiple catch blocks (S-2142)
    public void multipleCatchBlocks() {
        try {
            int result = 10 / 0;
        } catch (ArithmeticException e) {
            System.out.println("ArithmeticException");
        } catch (NullPointerException e) {
            System.out.println("NullPointerException");
        } catch (Exception e) {
            System.out.println("Exception");
        }
    }

    // VULN 91: Try-with-resources not used (S-2095)
    public void tryWithResourcesNotUsed() throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader("test.txt"));
        try {
            reader.readLine();
        } finally {
            reader.close();
        }
    }

    // VULN 92: Resource not closed in finally (S-2095)
    public void resourceNotClosedInFinally() throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader("test.txt"));
        try {
            reader.readLine();
        } finally {
            // reader.close(); // Missing close
        }
    }

    // VULN 93: Resource leak (S-2095)
    public void resourceLeak() throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader("test.txt"));
        reader.readLine();
        // reader.close(); // Missing close
    }

    // VULN 94: File not closed (S-2095)
    public void fileNotClosed() throws Exception {
        FileInputStream fis = new FileInputStream("test.txt");
        fis.read();
        // fis.close(); // Missing close
    }

    // VULN 95: Socket not closed (S-2095)
    public void socketNotClosed() throws Exception {
        java.net.Socket socket = new java.net.Socket("localhost", 8080);
        socket.getOutputStream().write(1);
        // socket.close(); // Missing close
    }

    // VULN 96: ServerSocket not closed (S-2095)
    public void serverSocketNotClosed() throws Exception {
        java.net.ServerSocket serverSocket = new java.net.ServerSocket(8080);
        serverSocket.accept();
        // serverSocket.close(); // Missing close
    }

    // VULN 97: DatagramSocket not closed (S-2095)
    public void datagramSocketNotClosed() throws Exception {
        java.net.DatagramSocket socket = new java.net.DatagramSocket(8080);
        socket.receive(new java.net.DatagramPacket(new byte[1024], 1024));
        // socket.close(); // Missing close
    }

    // VULN 98: MulticastSocket not closed (S-2095)
    public void multicastSocketNotClosed() throws Exception {
        java.net.MulticastSocket socket = new java.net.MulticastSocket(8080);
        socket.receive(new java.net.DatagramPacket(new byte[1024], 1024));
        // socket.close(); // Missing close
    }

    // VULN 99: URL not closed (S-2095)
    public void urlNotClosed() throws Exception {
        URL url = new URL("http://example.com");
        url.openStream();
        // url connection not closed
    }

    // VULN 100: JarFile not closed (S-2095)
    public void jarFileNotClosed() throws Exception {
        java.util.jar.JarFile jarFile = new java.util.jar.JarFile("test.jar");
        jarFile.entries();
        // jarFile.close(); // Missing close
    }

    // This class is intentionally never instantiated or used in production code
    private SonarQubeVulnerabilitiesDemo() {
        throw new UnsupportedOperationException("This class is for security testing only");
    }
}
