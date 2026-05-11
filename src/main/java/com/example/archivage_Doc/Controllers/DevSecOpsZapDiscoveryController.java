package com.example.archivage_Doc.Controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DevSecOpsZapDiscoveryController {

    // INTENTIONAL VULN - ZAP DEMO ONLY.
    // These endpoints help OWASP ZAP discover a controlled vulnerable demo page
    // without changing the Jenkins ZAP target URL.

    @GetMapping(value = "/robots.txt", produces = MediaType.TEXT_PLAIN_VALUE)
    public String robots(HttpServletRequest request) {
        String baseUrl = baseUrl(request);
        return """
                User-agent: *
                Allow: /api/test/devsecops/zap-demo
                Allow: /api/test/devsecops/sqli
                Allow: /api/test/devsecops/cmd
                Allow: /api/test/devsecops/path
                Allow: /api/test/devsecops/crypto
                Sitemap: %s/sitemap.xml
                """.formatted(baseUrl);
    }

    @GetMapping(value = "/sitemap.xml", produces = MediaType.APPLICATION_XML_VALUE)
    public String sitemap(HttpServletRequest request) {
        String baseUrl = baseUrl(request);
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                    <url><loc>%s/api/test/devsecops/zap-demo</loc></url>
                    <url><loc>%s/api/test/devsecops/sqli?username=admin</loc></url>
                    <url><loc>%s/api/test/devsecops/cmd?host=127.0.0.1</loc></url>
                    <url><loc>%s/api/test/devsecops/path?file=../../etc/passwd</loc></url>
                    <url><loc>%s/api/test/devsecops/crypto?value=demo</loc></url>
                </urlset>
                """.formatted(baseUrl, baseUrl, baseUrl, baseUrl, baseUrl);
    }

    @GetMapping(value = "/api/test/devsecops/zap-demo", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> zapDemoPage() {
        String html = """
                <!doctype html>
                <html lang="fr">
                <head>
                    <meta charset="UTF-8">
                    <title>DevSecOps ZAP Demo</title>
                    <script src="https://code.jquery.com/jquery-1.8.3.min.js"></script>
                    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.2.19/angular.min.js"></script>
                    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
                </head>
                <body>
                    <h1>Page volontairement vulnerable pour OWASP ZAP</h1>
                    <p>Cette page existe uniquement pour la demonstration DevSecOps PFE.</p>
                    <p>Elle charge volontairement de vieilles librairies JavaScript afin que ZAP puisse detecter des alertes HIGH via Retire.js.</p>

                    <!-- INTENTIONAL VULN - ZAP DEMO: debug token left in HTML comment: demo-zap-token-123456 -->

                    <nav>
                        <a href="/api/test/devsecops/sqli?username=admin">SQL Injection demo</a>
                        <a href="/api/test/devsecops/cmd?host=127.0.0.1">Command Injection demo</a>
                        <a href="/api/test/devsecops/path?file=../../etc/passwd">Path Traversal demo</a>
                        <a href="/api/test/devsecops/crypto?value=demo">Weak Crypto demo</a>
                    </nav>

                    <form action="/api/test/devsecops/sqli" method="get">
                        <label>Username</label>
                        <input name="username" value="admin' OR '1'='1">
                        <button type="submit">Tester SQLi</button>
                    </form>

                    <script>
                        // INTENTIONAL VULN - ZAP DEMO: dangerous JS sinks for passive scan visibility.
                        document.write(location.search);
                        if (location.hash.length > 1) {
                            eval(location.hash.substring(1));
                        }
                    </script>
                </body>
                </html>
                """;

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("X-Powered-By", "Express/3.0.0")
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    private String baseUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
    }
}
