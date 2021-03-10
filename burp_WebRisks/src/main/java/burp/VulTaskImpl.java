package burp;

import java.util.List;
import java.util.Locale;

public abstract class VulTaskImpl {

    IExtensionHelpers helpers;
    IBurpExtenderCallbacks callbacks;
    List<BurpExtender.LogEntry> log;
    IHttpRequestResponse messageInfo;
    int rows;

    VulTaskImpl(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo, int rows) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.log = log;
        this.messageInfo = messageInfo;
        this.rows = rows;
    }

    abstract VulResult run();

    //检查头部是否包含某信息
    String check(List<String> headers, String header){
        if (null == headers){
            return null;
        }
        for (String s : headers) {
            if (s.toLowerCase(Locale.ROOT).contains(header.toLowerCase(Locale.ROOT))){
                return s;
            }
        }
        return null;
    }
}
