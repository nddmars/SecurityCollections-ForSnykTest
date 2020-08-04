package com.utils.ssl.sslyze;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class JSSLyze {
    ProcessExecutor executor;
    SSLyzeConsoleOutputParser parser;
    String outputFilename = "sslyze.output";
    String pathToSslyze;
    static String output="\r\n" + 
    		" CHECKING HOST(S) AVAILABILITY\r\n" + 
    		" -----------------------------\r\n" + 
    		"\r\n" + 
    		"   ssros.ru:443                       => 185.125.217.182 \r\n" + 
    		"\r\n" + 
    		"\r\n" + 
    		"\r\n" + 
    		"\r\n" + 
    		" SCAN RESULTS FOR SSROS.RU:443 - 185.125.217.182\r\n" + 
    		" -----------------------------------------------\r\n" + 
    		"\r\n" + 
    		" * ROBOT Attack:\r\n" + 
    		"                                          OK - Not vulnerable.\r\n" + 
    		"\r\n" + 
    		" * OpenSSL CCS Injection:\r\n" + 
    		"                                          OK - Not vulnerable to OpenSSL CCS injection\r\n" + 
    		"\r\n" + 
    		" * Deflate Compression:\r\n" + 
    		"                                          OK - Compression disabled\r\n" + 
    		"\r\n" + 
    		" * Certificates Information:\r\n" + 
    		"       Hostname sent for SNI:             ssros.ru\r\n" + 
    		"       Number of certificates detected:   1\r\n" + 
    		"\r\n" + 
    		"\r\n" + 
    		"     Certificate #0 ( _RSAPublicKey )\r\n" + 
    		"       SHA1 Fingerprint:                  71fe8afee4b32b070a06872eb81ba32018e355ce\r\n" + 
    		"       Common Name:                       ssros.ru\r\n" + 
    		"       Issuer:                            Let's Encrypt Authority X3\r\n" + 
    		"       Serial Number:                     327784062194124668058431546925690770493499\r\n" + 
    		"       Not Before:                        2018-01-11\r\n" + 
    		"       Not After:                         2018-04-11\r\n" + 
    		"       Public Key Algorithm:              _RSAPublicKey\r\n" + 
    		"       Signature Algorithm:               sha256\r\n" + 
    		"       Key Size:                          2048\r\n" + 
    		"       Exponent:                          65537\r\n" + 
    		"       DNS Subject Alternative Names:     ['ssros.ru', 'www.ssros.ru']\r\n" + 
    		"\r\n" + 
    		"     Certificate #0 - Trust\r\n" + 
    		"       Hostname Validation:               OK - Certificate matches server hostname\r\n" + 
    		"       Android CA Store (9.0.0_r9):       FAILED - Certificate is NOT Trusted: unable to get local issuer certificate\r\n" + 
    		"       Apple CA Store (iOS 13, iPadOS 13, macOS 10.15, watchOS 6, and tvOS 13):FAILED - Certificate is NOT Trusted: unable to get local issuer certificate\r\n" + 
    		"       Java CA Store (jdk-13.0.2):        FAILED - Certificate is NOT Trusted: unable to get local issuer certificate\r\n" + 
    		"       Mozilla CA Store (2020-06-21):     FAILED - Certificate is NOT Trusted: unable to get local issuer certificate\r\n" + 
    		"       Windows CA Store (2020-05-04):     FAILED - Certificate is NOT Trusted: unable to get local issuer certificate\r\n" + 
    		"       Symantec 2018 Deprecation:         ERROR - Could not build verified chain (certificate untrusted?)\r\n" + 
    		"       Received Chain:                    ssros.ru\r\n" + 
    		"       Verified Chain:                    ERROR - Could not build verified chain (certificate untrusted?)\r\n" + 
    		"       Received Chain Contains Anchor:    ERROR - Could not build verified chain (certificate untrusted?)\r\n" + 
    		"       Received Chain Order:              OK - Order is valid\r\n" + 
    		"       Verified Chain contains SHA1:      ERROR - Could not build verified chain (certificate untrusted?)\r\n" + 
    		"\r\n" + 
    		"     Certificate #0 - Extensions\r\n" + 
    		"       OCSP Must-Staple:                  NOT SUPPORTED - Extension not found\r\n" + 
    		"       Certificate Transparency:          NOT SUPPORTED - Extension not found\r\n" + 
    		"\r\n" + 
    		"     Certificate #0 - OCSP Stapling\r\n" + 
    		"                                          NOT SUPPORTED - Server did not send back an OCSP response\r\n" + 
    		"\r\n" + 
    		" * SSL 2.0 Cipher suites:\r\n" + 
    		"     Attempted to connect using 7 cipher suites; the server rejected all cipher suites.\r\n" + 
    		"\r\n" + 
    		" * TLS 1.1 Cipher suites:\r\n" + 
    		"     Attempted to connect using 80 cipher suites.\r\n" + 
    		"\r\n" + 
    		"     The server accepted the following 17 cipher suites:\r\n" + 
    		"        TLS_RSA_WITH_SEED_CBC_SHA                         128                      \r\n" + 
    		"        TLS_RSA_WITH_RC4_128_SHA                          128                      \r\n" + 
    		"        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 256                      \r\n" + 
    		"        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 128                      \r\n" + 
    		"        TLS_RSA_WITH_AES_256_CBC_SHA                      256                      \r\n" + 
    		"        TLS_RSA_WITH_AES_128_CBC_SHA                      128                      \r\n" + 
    		"        TLS_RSA_WITH_3DES_EDE_CBC_SHA                     168                      \r\n" + 
    		"        TLS_ECDHE_RSA_WITH_RC4_128_SHA                    128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA               168       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_DHE_RSA_WITH_SEED_CBC_SHA                     128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                 168       DH (2048 bits) \r\n" + 
    		"\r\n" + 
    		"     The group of cipher suites supported by the server has the following properties:\r\n" + 
    		"       Forward Secrecy                    OK - Supported\r\n" + 
    		"       Legacy RC4 Algorithm               INSECURE - Supported\r\n" + 
    		"\r\n" + 
    		"     The server has no preferred cipher suite.\r\n" + 
    		"\r\n" + 
    		"\r\n" + 
    		" * TLS 1.2 Cipher suites:\r\n" + 
    		"     Attempted to connect using 158 cipher suites.\r\n" + 
    		"\r\n" + 
    		"     The server accepted the following 30 cipher suites:\r\n" + 
    		"        TLS_RSA_WITH_SEED_CBC_SHA                         128                      \r\n" + 
    		"        TLS_RSA_WITH_RC4_128_SHA                          128                      \r\n" + 
    		"        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 256                      \r\n" + 
    		"        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 128                      \r\n" + 
    		"        TLS_RSA_WITH_AES_256_GCM_SHA384                   256                      \r\n" + 
    		"        TLS_RSA_WITH_AES_256_CBC_SHA256                   256                      \r\n" + 
    		"        TLS_RSA_WITH_AES_256_CBC_SHA                      256                      \r\n" + 
    		"        TLS_RSA_WITH_AES_128_GCM_SHA256                   128                      \r\n" + 
    		"        TLS_RSA_WITH_AES_128_CBC_SHA256                   128                      \r\n" + 
    		"        TLS_RSA_WITH_AES_128_CBC_SHA                      128                      \r\n" + 
    		"        TLS_RSA_WITH_3DES_EDE_CBC_SHA                     168                      \r\n" + 
    		"        TLS_ECDHE_RSA_WITH_RC4_128_SHA                    128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             256       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384             256       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256             128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA               168       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_DHE_RSA_WITH_SEED_CBC_SHA                     128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384               256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256               256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256               128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256               128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                 168       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                 168       DH (2048 bits) \r\n" + 
    		"\r\n" + 
    		"     The group of cipher suites supported by the server has the following properties:\r\n" + 
    		"       Forward Secrecy                    OK - Supported\r\n" + 
    		"       Legacy RC4 Algorithm               INSECURE - Supported\r\n" + 
    		"\r\n" + 
    		"     The server has no preferred cipher suite.\r\n" + 
    		"\r\n" + 
    		"\r\n" + 
    		" * Session Renegotiation:\r\n" + 
    		"       Client-initiated Renegotiation:    OK - Rejected\r\n" + 
    		"       Secure Renegotiation:              OK - Supported\r\n" + 
    		"\r\n" + 
    		" * TLS 1.0 Cipher suites:\r\n" + 
    		"     Attempted to connect using 80 cipher suites.\r\n" + 
    		"\r\n" + 
    		"     The server accepted the following 17 cipher suites:\r\n" + 
    		"        TLS_RSA_WITH_SEED_CBC_SHA                         128                      \r\n" + 
    		"        TLS_RSA_WITH_RC4_128_SHA                          128                      \r\n" + 
    		"        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 256                      \r\n" + 
    		"        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 128                      \r\n" + 
    		"        TLS_RSA_WITH_AES_256_CBC_SHA                      256                      \r\n" + 
    		"        TLS_RSA_WITH_AES_128_CBC_SHA                      128                      \r\n" + 
    		"        TLS_RSA_WITH_3DES_EDE_CBC_SHA                     168                      \r\n" + 
    		"        TLS_ECDHE_RSA_WITH_RC4_128_SHA                    128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA               168       ECDH: prime256v1 (256 bits)\r\n" + 
    		"        TLS_DHE_RSA_WITH_SEED_CBC_SHA                     128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  256       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  128       DH (2048 bits) \r\n" + 
    		"        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                 168       DH (2048 bits) \r\n" + 
    		"\r\n" + 
    		"     The group of cipher suites supported by the server has the following properties:\r\n" + 
    		"       Forward Secrecy                    OK - Supported\r\n" + 
    		"       L...";

    public JSSLyze(String pathToSslyze) {
        this.pathToSslyze = pathToSslyze;
    }

    public JSSLyze(String pathToSslyze, String outputFilename) {
        this(pathToSslyze);
        this.outputFilename = outputFilename;
    }

    public void execute(String options, String host, int port) throws IOException {
        List<String> cmds = new ArrayList<String>();
        cmds.add(pathToSslyze);
        cmds.addAll(Arrays.asList(options.split("\\s+")));
        if (port > -1) {
            host = host + ":" + port;
        }
        cmds.add(host);
        executor = new ProcessExecutor(cmds);
        executor.setFilename(outputFilename);
        executor.start();
        output = executor.getOutput();
        parser = new SSLyzeConsoleOutputParser(output);
    }

    public SSLyzeConsoleOutputParser getParser() {
        return parser;
    }

    public String getOutput() {
        return output;
    }

   public static void main(String a[])
   {
	   JSSLyze ssl= new JSSLyze("C:\\tools\\sslyze-3.0.8-exe\\sslyze-3.0.8-exe\\sslyze.exe");
	   try {
		ssl.execute("--regular", "ssros.ru", 443);
		
	   
		   //SSLyzeConsoleOutputParser parser = new SSLyzeConsoleOutputParser(Files.readString(Path.of("C:\\tools\\sslyze-3.0.8-exe\\sslyze-3.0.8-exe\\test.txt")));
		  //System.out.println(parser.listAllAcceptedCiphers());

	} catch (Exception e) {
		e.printStackTrace();
	}
   }
}