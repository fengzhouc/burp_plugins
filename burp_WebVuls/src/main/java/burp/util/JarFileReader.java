package burp.util;

import org.apache.commons.io.IOUtils;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static burp.BurpExtender.callbacks;

public class JarFileReader {
    public String read(String filepath) {
        String fileContent = "";
        InputStream inputStream = null;
        try{
            inputStream = JarFileReader.class.getClassLoader().getResourceAsStream(filepath);
            if (inputStream != null) {
                StringBuilder textBuilder = new StringBuilder();
                try (Reader reader = new BufferedReader(new InputStreamReader
                        (inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
                    int c = 0;
                    while ((c = reader.read()) != -1) {
                        textBuilder.append((char) c);
                    }
                }
                fileContent = textBuilder.toString();
            }else{
                callbacks.printError("[*] No file was found in the jar: " + filepath);
            }
        }catch (Exception e){
            OutputStream out = callbacks.getStderr();
            PrintWriter p = new PrintWriter(out);
            e.printStackTrace(p);
            try {
                p.flush();
                out.flush();
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
        return fileContent;
    }

    public static void main(String[] args){
        new JarFileReader().read("CVE_2020_14882_14883_xml.tpl");
    }
}
