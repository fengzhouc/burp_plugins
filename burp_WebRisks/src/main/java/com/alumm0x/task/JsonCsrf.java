package com.alumm0x.task;

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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class JsonCsrf extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new JsonCsrf(requestResponse);
    }
    private JsonCsrf(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、jsonCsrf：修改content-type为form表单的
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //csrf会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Cookie") != null){
                /*
                 * 1、请求头包含application/json
                 */
                String ct = ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-Type");
                if (ct != null && ct.contains("application/json")) {
                    List<String> new_headers = new ArrayList<String>();
                    String CT = "Content-Type: application/x-www-form-urlencoded";
                    //新请求修改content-type
                    boolean hasCT = false;
                    for (String header :
                            BurpReqRespTools.getReqHeaders(requestResponse)) {
                        // 剔除掉csrf头部
                        if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                            if (header.toLowerCase(Locale.ROOT).contains("content-type")) {
                                header = header.replace("application/json", "application/x-www-form-urlencoded");
                                hasCT = true;
                            }
                            new_headers.add(header);
                        }
                    }
                    //如果请求头中没有CT，则添加一个
                    if (!hasCT) {
                        new_headers.add(CT);
                    }
                    if (!BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("get")) {
                        //新的请求包:content-type
                        okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            new_headers, 
                            BurpReqRespTools.getQuery(requestResponse), 
                            new String(BurpReqRespTools.getReqBody(requestResponse)), 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new JsonCsrfCallback(this));
                    }
                }
            }
        }
    }
}

class JsonCsrfCallback implements Callback {

    VulTaskImpl vulTask;

    public JsonCsrfCallback(VulTaskImpl vulTask){
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
            "[JsonCsrfCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            //如果状态码相同则可能存在问题
            if (BurpReqRespTools.getStatus(requestResponse) == BurpReqRespTools.getStatus(vulTask.requestResponse)
                && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse))) {
                message = "JsonCsrf";
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
