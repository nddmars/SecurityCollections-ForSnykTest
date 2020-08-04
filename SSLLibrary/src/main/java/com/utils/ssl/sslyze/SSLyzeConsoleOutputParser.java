package com.utils.ssl.sslyze;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

public class SSLyzeConsoleOutputParser {
    String output;
    final static String NEWLINE = "\r\n|[\n\r\u2028\u2029\u0085]";

    public SSLyzeConsoleOutputParser(String output) {
        this.output = output;
    }

    public List<CipherElement> listPreferredCipherSuitesFor(String protocol) {
   
    	try(Scanner lineScanner = new Scanner(output).useDelimiter(NEWLINE)){
        while (lineScanner.hasNext()) {
            if (lineScanner.next().contains(protocol + " Cipher suites")) break;
        }
        lineScanner.next();
        List<CipherElement> preferredList = new ArrayList<CipherElement>();
        while (lineScanner.hasNext()) {
            String line = lineScanner.next();
            if (line.contains("* ")) {
                break;
            } else if(line.contains("The server is configured to prefer")) {
            	 line = lineScanner.next();
                Scanner wordScanner = new Scanner(line);
                String name = wordScanner.next();
                int size = wordScanner.nextInt();
                preferredList.add(new CipherElement(name,size));
                wordScanner.close();
            }
        }
        return preferredList;
        }
    }

    public List<String> listPreferredCipherSuiteNamesFor(String protocol) {
        List<String> names = new ArrayList<String>();
        for (CipherElement element : listPreferredCipherSuitesFor(protocol)) {
            names.add(element.getName());
        }
        return names;
    }

    public List<String> listAcceptedCipherSuiteNamesFor(String protocol) {
        List<String> names = new ArrayList<String>();
        for (CipherElement element : listAcceptedCipherSuitesFor(protocol)) {
            names.add(element.getName());
        }
        return names;
    }

    public List<String> listAllSupportedProtocols() {
        List<String> protocolList = new ArrayList<String>();
        try(Scanner lineScanner = new Scanner(output).useDelimiter(NEWLINE)){
        String line;
        while (lineScanner.hasNext()) {
            line = lineScanner.next();
            if (line.contains("Cipher suites:")) {
                String nextLine = lineScanner.next();
                if (!nextLine.contains("rejected")) {
                    Scanner wordScanner = new Scanner(line);
                    wordScanner.next();
                    protocolList.add(wordScanner.next()+" "+wordScanner.next());
                    wordScanner.close();
                }
            }
        }
        return protocolList;
        }
    }

    public List<String> listAllAcceptedCiphers() {
        List<String> all = new ArrayList<String>();
        for (String protocol : listAllSupportedProtocols()) {
            all.addAll(listAcceptedCipherSuiteNamesFor(protocol));
        }
        return all;
    }

    public int findSmallestAcceptedKeySize() {
        List<Integer> all = new ArrayList<Integer>();
        for (String protocol : listAllSupportedProtocols()) {
            all.add(findSmallestAcceptedKeySize(protocol));
        }
        Collections.sort(all);
        if (all.size() == 0) throw new RuntimeException("No keys found.");
        return all.get(0);
    }

    public int findSmallestAcceptedKeySize(String protocol) {
        List<Integer> all = new ArrayList<Integer>();
        for (CipherElement cipherElement : listAcceptedCipherSuitesFor(protocol)) {
            all.add(cipherElement.getSize());
        }
        Collections.sort(all);
        if (all.size() == 0) throw new RuntimeException("No keys found for protocol "+protocol);
        return all.get(0);
    }

    public List<CipherElement> listAcceptedCipherSuitesFor(String protocol) {
    	try(Scanner lineScanner = new Scanner(output).useDelimiter(NEWLINE)){
         while (lineScanner.hasNext()) {
            if (lineScanner.next().contains(protocol + " Cipher suites")) break;
        }
        while (lineScanner.hasNext()) {
            String line = lineScanner.next();
            if (line.contains("server accepted") || line.contains("server rejected")) break;
        }
        List<CipherElement> acceptedCipherList = new ArrayList<CipherElement>();
        while (lineScanner.hasNext()) {
            String line = lineScanner.next();
            if (line.length() == 0 || line.contains("Undefined")) {
                break;
            } else {
                Scanner wordScanner = new Scanner(line);
                String name = wordScanner.next();
                int size = wordScanner.nextInt();
                acceptedCipherList.add(new CipherElement(name,size));
                wordScanner.close();
            }
        }
        return acceptedCipherList;
    	}
    }

    public boolean acceptsCipherWithPartialName(String name) {
        for (String cipher : listAllAcceptedCiphers()) {
            if (cipher.toUpperCase().contains(name.toUpperCase())) return true;
        }
        return false;
    }

    public boolean acceptsCipher(String name) {
        for (String cipher : listAllAcceptedCiphers()) {
            if (cipher.toUpperCase().equals(name.toUpperCase())) return true;
        }
        return false;
    }

    public boolean doesAnyLineMatch(String regex) {
        Scanner lineScanner = new Scanner(output).useDelimiter(NEWLINE);
        while (lineScanner.hasNext()) {
            if (lineScanner.next().matches(regex)) return true;
        }
        return false;
    }

    private class CipherElement {
        String name;
        int size;

        public CipherElement(String name, int size) {
            this.name = name;
            this.size = size;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getSize() {
            return size;
        }

        public void setSize(int size) {
            this.size = size;
        }
    }
    
    public static void main(String a[]) throws IOException
    {
 	    SSLyzeConsoleOutputParser parser = new SSLyzeConsoleOutputParser(Files.readString(Path.of("C:\\tools\\sslyze-3.0.8-exe\\sslyze-3.0.8-exe\\test2.txt")));
 	    System.out.println(parser.listPreferredCipherSuitesFor("TLS 1.3"));

    }   
}