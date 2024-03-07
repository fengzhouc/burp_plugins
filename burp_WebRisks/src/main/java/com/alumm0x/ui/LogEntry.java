package com.alumm0x.ui;

import org.jetbrains.annotations.NotNull;

import burp.IHttpRequestResponsePersisted;

//存在漏洞的url信息类
//log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
//                            host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
public class LogEntry implements Comparable
{
    public final int id;
    public final IHttpRequestResponsePersisted requestResponse;
    //final URL url;
    public final String Host;
    public final String Path;
    public final String Method;
    public final short Status;
    public final String Risk;
    public final String Desc;


    public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String method, short status, String risk, String desc)
    {
        this.Status = status;
        this.id = id;
        this.requestResponse = requestResponse;
        //this.Url = url;
        this.Method = method;
        this.Path = path;
        this.Host = host;
        this.Risk = risk;
        this.Desc = desc;
    }

    @Override
    public int compareTo(@NotNull Object o) {
        String p = ((LogEntry)o).Path;
        //如果相等则不动
        if (this.Path.equalsIgnoreCase(p)) {
            return -1;
        }
        //其他情况都返回小于的情况
        return -1;
    }
}
