package com.alumm0x.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;

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

    // 改用第三方的发包器-okhttp3
    // 并发说明 https://juejin.cn/post/6949527136088621070
    // 基本使用 https://mp.weixin.qq.com/s?__biz=MzU2NjgwNjc0NQ==&mid=2247483867&idx=1&sn=fda05eb481bd1d2c7a52b8e41c01de8c&chksm=fca7906dcbd0197b2c6af55af2843edf7db987ca19659ea72119563100f2c59976e657fa7a6b&scene=21#wechat_redirect
    // 工作流 https://cloud.tencent.com/developer/article/1667339
    public IHttpRequestResponse send(IHttpService iHttpService, List<String> headers, byte[] body){
        //新的请求包
        byte[] req = this.helpers.buildHttpMessage(headers, body);
//        callbacks.printError("send: \n" + new String(req));
        //返回响应
        return this.callbacks.makeHttpRequest(iHttpService, req);
    }
}
