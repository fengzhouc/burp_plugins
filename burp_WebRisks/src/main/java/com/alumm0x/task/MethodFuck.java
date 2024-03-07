package com.alumm0x.task;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MethodFuck extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new MethodFuck(requestResponse);
    }
    private MethodFuck(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、尝试其他method是否可以请求通，有可能是同一个api不同的method，主要是get/post/put/patch
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            List<String> methods = new ArrayList<>();
            methods.add("GET");
            methods.add("POST");
            methods.add("PUT");
            methods.add("PATCH");
            String c_method = BurpReqRespTools.getMethod(requestResponse);
            if (methods.contains(c_method)) {
                methods.remove(c_method); //删除已有的，检测其他的
                for (String method : methods) {
                    //新的请求包
                    okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            method, 
                            BurpReqRespTools.getReqHeaders(requestResponse), 
                            BurpReqRespTools.getQuery(requestResponse), 
                            new String(BurpReqRespTools.getReqBody(requestResponse)), 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new MethodFuckCallback(this));
                }
            }
        }
    }
}

class MethodFuckCallback implements Callback {

    VulTaskImpl vulTask;

    public MethodFuckCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        // 记录日志
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, null, vulTask.requestResponse);
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            MethodFuck.class.getSimpleName(),
            "onFailure", 
            "[MethodFuckCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (BurpReqRespTools.getStatus(requestResponse) == 200
                || BurpReqRespTools.getStatus(requestResponse) == 302) {
            message = "MethodFuck-" + call.request().method();
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            MethodFuck.class.getSimpleName(),
            message, 
            null);
    }
}