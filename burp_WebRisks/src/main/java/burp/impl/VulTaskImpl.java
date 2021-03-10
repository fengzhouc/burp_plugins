package burp.impl;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.List;
import java.util.Locale;

public abstract class VulTaskImpl {

    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    protected List<BurpExtender.LogEntry> log;
    protected IHttpRequestResponse messageInfo;
    protected int rows;

    public VulTaskImpl(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo, int rows) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.log = log;
        this.messageInfo = messageInfo;
        this.rows = rows;
    }

    public abstract VulResult run();

    //检查头部是否包含某信息
    protected String check(List<String> headers, String header){
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
