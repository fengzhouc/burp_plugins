package burp.vuls;

import burp.*;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class Tomcat {

    public static String CVE_2017_12615_poc = "##Condition##\n" +
            "Apache tomcat 7.0.0 to 7.0.79\n" +
            "\n" +
            "##POC##\n" +
            "#Request\n" +
            "PUT /shell.jsp/ HTTP:1.1\n" +
            "Host: hack.com\n" +
            "......\n" +
            "\n" +
            "<shellcode>\n" +
            "\n" +
            "#Responce\n" +
            "201 Create HTTP/1.1\n" +
            "......\n";

    public static void CVE_2017_12615() {
        String poc = CVE_2017_12615_poc;

        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        String payload = "";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
        Thread thread = new Thread(httpRequestThread);
        thread.start();
        try {
            // 等待，直到运行结束
            thread.join();
        } catch (InterruptedException e) {
            OutputStream out = BurpExtender.callbacks.getStderr();
            PrintWriter p = new PrintWriter(out);
            e.printStackTrace(p);
            try {
                p.flush();
                out.flush();
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
        HttpResult httpResult = httpRequestThread.getResulemessageInfo();
        if (collaboratorClientContext.fetchCollaboratorInteractionsFor(val).size() != 0) {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "CVE-2019-0230(S2-059)", poc, "hack!"));
        }else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "CVE-2019-0230(S2-059)", poc, "pass"));
        }
    }
}
