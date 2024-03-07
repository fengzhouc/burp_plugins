package com.alumm0x.task;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.JsonTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XssReflect extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new XssReflect(requestResponse);
    }
    private XssReflect(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特使flag
         * 2、然后检查响应头是否存在flag
         * */
        String xssflag = BurpExtender.helpers.urlEncode("_<xss/>'\"flag");
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){

            //反射型只测查询参数
            String new_query = "";
            if (BurpReqRespTools.getQuery(requestResponse) != null) {
                new_query = JsonTools.createFormBody(BurpReqRespTools.getQuery(requestResponse), xssflag);
            }else {
                // 没有查询参数的话，插入一个试试，为啥这个搞呢，有些会把url潜入到页面中，比如错误信息的时候，所以这时如果没有防护，那基本就存在问题的
                new_query = "test=" + xssflag;
            }
            //新的请求包
            okHttpRequester.send(
                BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                BurpReqRespTools.getMethod(requestResponse), 
                BurpReqRespTools.getReqHeaders(requestResponse), 
                new_query, 
                new String(BurpReqRespTools.getReqBody(requestResponse)), 
                BurpReqRespTools.getContentType(requestResponse), 
                new XssReflectCallback(this));

        }
    }
}

class XssReflectCallback implements Callback {

    VulTaskImpl vulTask;

    public XssReflectCallback(VulTaskImpl vulTask){
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
            XssReflect.class.getSimpleName(),
            "onFailure", 
            "[XssReflectCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        String ct = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Content-Type");
        // 反射性仅存在于响应content-type是页面等会被浏览器渲染的资源，比如json响应是没有的，有也是dom型
        if(ct != null && (
            ct.contains("text/html") 
            || ct.contains("application/xhtml+xml")
            || ct.contains("application/x-www-form-urlencoded")
            || ct.contains("image/svg+xml")
            )){
            // 检查响应中是否存在flag
            String respBody = new String(BurpReqRespTools.getRespBody(requestResponse));
            if (respBody.contains("_<xss/>'\"flag")) {
                message = "XssReflect";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            XssReflect.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/XssReflect.bbm")));
    }
}