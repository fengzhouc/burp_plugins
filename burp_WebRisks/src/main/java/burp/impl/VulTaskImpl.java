package burp.impl;

import burp.*;

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

    /*
    * TODO 漏洞检测任务的具体逻辑
    * */
    public abstract VulResult run();


    //检查头部是否包含某信息
    //头部信息包含如下
    //1、请求头/响应头
    //2、首部
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
    // 添加面板展示数据
    // 已经在列表的不添加
    protected String logAdd(int id, IHttpRequestResponse requestResponse, String host, String path, String method, Short status, String risk){
        boolean inside = false;
        for (BurpExtender.LogEntry le :
                log) {
            if (le.Host.equalsIgnoreCase(host)
                    && le.Path.equalsIgnoreCase(path)
                    && le.Method.equalsIgnoreCase(method)
                    && le.Status.equals(status)
                    && le.Risk.equalsIgnoreCase(risk) ) {
                inside = true;
                break;
            }
        }
        if (!inside){
            log.add(new BurpExtender.LogEntry(id, callbacks.saveBuffersToTempFiles(requestResponse),
                    host, path, method, status, risk));
            return "success";
        }
        return "inside";
    }
}
