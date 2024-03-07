package com.alumm0x.task.config;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.HeaderTools;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Cors extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Cors(requestResponse);
    }
    private Cors(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、cors
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            /*
                * ajax请求跨域获取数据的条件
                * 1、Access-Control-Allow-Credentials为true
                * 2、Access-Control-Allow-Origin为*或者根据origin动态设置
                */
            if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Access-Control-Allow-Origin") != null){
                String origin = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Access-Control-Allow-Origin");
                String credentials = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse),  "Access-Control-Allow-Credentials");
                if (credentials != null && credentials.contains("true")){
                    if (origin.contains("*")) {
                        MainPanel.logAdd(
                            requestResponse, 
                            BurpReqRespTools.getHost(requestResponse), 
                            BurpReqRespTools.getUrlPath(requestResponse),
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getStatus(requestResponse), 
                            Cors.class.getSimpleName(),
                            "CORS Any", 
                            null);
                    }else {
                        List<String> new_headers = new ArrayList<String>();
                        String evilOrigin = "http://evil.com";
                        //新请求修改origin
                        for (String header :
                                BurpReqRespTools.getReqHeaders(requestResponse)) {
                            // 剔除掉csrf头部
                            if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                                if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                                    new_headers.add(header);
                                }
                            }
                        }
                        new_headers.add("Origin: "+evilOrigin);
                        okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            new_headers, 
                            BurpReqRespTools.getQuery(requestResponse), 
                            new String(BurpReqRespTools.getReqBody(requestResponse)), 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new CorsCallback(this));
                    }
                }
            }
        }
    }
}

class CorsCallback implements Callback {

    VulTaskImpl vulTask;

    public CorsCallback(VulTaskImpl vulTask){
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
            Cors.class.getSimpleName(),
            "onFailure", 
            "[CorsCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Access-Control-Allow-Origin").contains("http://evil.com")){
            message = "CORS Dynamic and Without csrfToken";
        }
        MainPanel.logAdd(
                requestResponse, 
                BurpReqRespTools.getHost(requestResponse), 
                BurpReqRespTools.getUrlPath(requestResponse),
                BurpReqRespTools.getMethod(requestResponse), 
                BurpReqRespTools.getStatus(requestResponse), 
                Cors.class.getSimpleName(),
                message, 
                null);
    }
}