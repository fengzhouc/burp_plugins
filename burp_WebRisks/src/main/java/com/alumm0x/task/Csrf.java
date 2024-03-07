package com.alumm0x.task;

import burp.IHttpRequestResponse;
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

public class Csrf extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Csrf(requestResponse);
    }
    private Csrf(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、Csrf-form表单
         *   （1）检查content为form表单
         *   （2）删除token请求头重放，看是否响应跟原响应一致
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Cookie") != null){
                //要包含centen-type,且为form表单，这里就会吧get排除掉了
                String ct = ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-Type");
                if (ct != null && ct.contains("application/x-www-form-urlencoded")){
                    List<String> new_headers = new ArrayList<>();
                    //新请求修改origin
                    for (String header : BurpReqRespTools.getReqHeaders(requestResponse)) {
                        // 剔除掉csrf头部
                        if (HeaderTools.inNormal(header.split(":")[0])) {
                            if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                                new_headers.add(header);
                            }
                        }
                    }
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        new_headers, 
                        BurpReqRespTools.getQuery(requestResponse), 
                        new String(BurpReqRespTools.getReqBody(requestResponse)), 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new CsrfCallback(this));
                }
            }
        }
    }
}

class CsrfCallback implements Callback {

    VulTaskImpl vulTask;

    public CsrfCallback(VulTaskImpl vulTask){
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
            "[CsrfCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            //如果状态码相同及响应内容一样，则可能存在问题
            if (BurpReqRespTools.getStatus(requestResponse) == BurpReqRespTools.getStatus(vulTask.requestResponse)
                    && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse))) {
                message = "formCsrf";
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