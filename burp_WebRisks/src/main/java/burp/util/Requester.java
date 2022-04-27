package burp.util;

import burp.*;

import java.util.List;

public class Requester {

    //单例模式
    private static Requester requester = null;
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;

    private Requester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers){
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    public static Requester getInstance(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers){
        if (requester == null){
            requester = new Requester(callbacks, helpers);
        }
        return requester;
    }

    public IHttpRequestResponse send(IHttpService iHttpService, List<String> headers, byte[] body){
        //新的请求包
        byte[] req = this.helpers.buildHttpMessage(headers, body);
        //返回响应
        return this.callbacks.makeHttpRequest(iHttpService, req);
    }
}
