package com.alumm0x.task;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;

public class Jsonp extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Jsonp(requestResponse);
    }
    private Jsonp(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、无字段则添加字段在测试
         * */
        // 后缀检查，静态资源不做测试
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), new ArrayList<>())){
            //jsonp只检测get请求
            if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("get")){
                //1.请求的url中含Jsonp敏感参数
                String query = BurpReqRespTools.getQuery(requestResponse);
                if (query.contains("callback=")
                        || query.contains("cb=")
                        || query.contains("jsonp")
                        || query.contains("json=")
                        || query.contains("call=")
                        || query.contains("jsonpCallback=")
                ) {
                    if (BurpReqRespTools.getStatus(requestResponse) == 200 && ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Centent-Type").contains("application/javascript")) { //状态码200才直接添加
                        MainPanel.logAdd(
                            requestResponse, 
                            BurpReqRespTools.getHost(requestResponse), 
                            BurpReqRespTools.getUrlPath(requestResponse),
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getStatus(requestResponse), 
                            "Jsonp, has query", 
                            null);
                    }
                }

                //2.url不含敏感参数,添加参数测试
                else {
                    String new_query = "";
                    //url有参数
                    if (!BurpReqRespTools.getQuery(requestResponse).equals("")) {
                        new_query = "call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert&jsonpCallback=qwert&" + query;
                    } else {//url无参数
                        new_query = "call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert&jsonpCallback=qwert";
                    }
                    //新的请求包
                    okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getReqHeaders(requestResponse), 
                            new_query, 
                            new String(BurpReqRespTools.getReqBody(requestResponse)), 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new JsonpCallback(this));
                }
            }
        }
    }
}

class JsonpCallback implements Callback {

    VulTaskImpl vulTask;

    public JsonpCallback(VulTaskImpl vulTask){
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
            "onFailure", 
            "[JsonpCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            String ct = ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-Type");
            //如果状态码相同则可能存在问题
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("qwert") && ct != null && ct.contains("application/javascript")) {
                message = "Jsonp";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            message, 
            null);
    }
}
