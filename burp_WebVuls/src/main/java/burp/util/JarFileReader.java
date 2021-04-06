package burp.util;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;

import static burp.BurpExtender.callbacks;

public class JarFileReader {
    public String read(String filepath) {
        String fileContent = "";
        InputStream inputStream = null;
        try{
            inputStream = JarFileReader.class.getClassLoader().getResourceAsStream(filepath);
            if (inputStream != null) {
                fileContent = IOUtils.toString(inputStream);
                inputStream.close();
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
