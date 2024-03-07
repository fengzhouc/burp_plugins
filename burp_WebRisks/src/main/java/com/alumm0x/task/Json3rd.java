package com.alumm0x.task;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.JsonTools;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Json3rd extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Json3rd(requestResponse);
    }
    private Json3rd(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、注入引号，造成服务器异常，返回堆栈信息
         * 2、检查堆栈信息，看是否有关键字，如fastjson等
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //如果有body参数，需要多body参数进行测试
            if (BurpReqRespTools.getReqBody(requestResponse).length > 0){
                if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-type") != null && ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-type").contains("application/json")){
                    String is = "'\""; //json格式的使用转义后的，避免json格式不正确
                    String req_body = JsonTools.createJsonBody(new String(BurpReqRespTools.getReqBody(requestResponse)), is);
                    //新的请求包
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        BurpReqRespTools.getQuery(requestResponse), 
                        req_body, 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new Json3rdCallback(this));
                }
            }
        }
    }

}

class Json3rdCallback implements Callback {

    VulTaskImpl vulTask;

    public Json3rdCallback(VulTaskImpl vulTask){
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
            Json3rd.class.getSimpleName(),
            "onFailure", 
            "[Json3rdCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        String respBpdy = new String(BurpReqRespTools.getRespBody(requestResponse));
        // 检查响应中是否存在flag
        if (respBpdy.contains("fastjson")) {
            message = "fastjson";
        }else if (respBpdy.contains("jackson")) {
            message = "jackson";
        }else if (respBpdy.contains("gson")) {
            message = "gson";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            Json3rd.class.getSimpleName(),
            message, 
            null);
    }
}