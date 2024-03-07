package com.alumm0x.task;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class IDOR_xy extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new IDOR_xy(requestResponse);
    }
    private IDOR_xy(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 横向越权
         * 检测逻辑
         * 1、设置别的用户cookie
         * 2、填充cookie重放，比对响应
         * */
        // 没有设置越权测试的cookie则不测试
        if (!MainPanel.cookie.equalsIgnoreCase("Cookie: xxx")){
            // 后缀检查，静态资源不做测试
            List<String> add = new ArrayList<String>();
            add.add(".js");
            if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
                //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
                // 只测试原本有cookie的请求
                List<String> new_headers = new ArrayList<String>();
                for (String header :
                        BurpReqRespTools.getReqHeaders(requestResponse)) {
                    //替换cookie
                    String[] auth = MainPanel.cookie.split(":");
                    String key = auth[0];
                    String value = auth[1];
                    if (header.toLowerCase(Locale.ROOT).startsWith(key.toLowerCase(Locale.ROOT))) {
                        header = key + ":" + value;
                    }
                    new_headers.add(header);
                }
                //新的请求包
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    new_headers, 
                    BurpReqRespTools.getQuery(requestResponse), 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new IDORxyCallback(this));
            }
        }
    }
}

class IDORxyCallback implements Callback {

    VulTaskImpl vulTask;

    public IDORxyCallback(VulTaskImpl vulTask){
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
            "[IDORxyCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            //如果状态码相同则可能存在问题
            if (BurpReqRespTools.getStatus(requestResponse) == BurpReqRespTools.getStatus(vulTask.requestResponse)
                    && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse))) {
                message = "IDOR_xy";
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