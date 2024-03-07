package com.alumm0x.task;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ssrf extends VulTaskImpl {

    String OriginDM = ""; // 记录原domain

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Ssrf(requestResponse);
    }
    private Ssrf(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            String regex = "http[s]?://(.*?)[/&\"]+?\\w*?"; //分组获取域名
            String evilHost = "evil6666.com";
            String query = BurpReqRespTools.getQuery(requestResponse);
            String request_body_str = new String(BurpReqRespTools.getReqBody(requestResponse));
            //如果有body参数，需要多body参数进行测试
            if (request_body_str.length() > 0){
                //1.先检测是否存在url地址的参数，正则匹配
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(request_body_str);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String domain = matcher.group(1);
                    OriginDM = domain;
                    // 修改为别的域名
                    String req_body = request_body_str.replace(domain, evilHost);
                    //新的请求包
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        query, 
                        req_body, 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new SsrfCallback(this));
                }
            }else if (query != null){
                //1.先检测是否存在url地址的参数，正则匹配
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(query);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String domain = matcher.group(1);
                    OriginDM = domain;
                    // callbacks.printOutput(domain);
                    // 修改为别的域名
                    String req_query = query.replace(domain, evilHost);
                    //新的请求包
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        req_query, 
                        new String(BurpReqRespTools.getReqBody(requestResponse)), 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new SsrfCallback(this));
                }
            }
        }
    }

}

class SsrfCallback implements Callback {

    VulTaskImpl vulTask;

    public SsrfCallback(VulTaskImpl vulTask){
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
            "[SsrfCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        // 检查响应中是否存在flag
        if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("evil6666.com")) {
            message = "SSRF, OriginDM: "+ ((Ssrf)vulTask).OriginDM;
        }else if (response.isSuccessful()){
            // 可能响应并没有回馈，所以这时响应是成功的也告警
            message = "SSRF, Not in Resp, OriginDM: "+ ((Ssrf)vulTask).OriginDM;
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/SsrfRegex.bbm")));
    }
}