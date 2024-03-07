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
import java.util.List;
import java.util.Locale;

public class WebSocketHijacking extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new WebSocketHijacking(requestResponse);
    }
    private WebSocketHijacking(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * websocket的csrf，类似jsonp，是不受cors限制的
         *   1.使用cookie
         *   2.修改/添加请求头Origin为http://evil.com，看是否能连接成功
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Cookie") != null){
                /*
                 * websocket请求跨域连接
                 * 修改origin
                 */
                if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Sec-WebSocket-Key") != null){
                    List<String> new_headers = new ArrayList<>();
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
                    new_headers.add("Origin: " + evilOrigin);
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        new_headers, 
                        BurpReqRespTools.getQuery(requestResponse), 
                        new String(BurpReqRespTools.getReqBody(requestResponse)), 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new WebSocketHijackingCallback(this));
                }
            }
        }
    }
}

class WebSocketHijackingCallback implements Callback {

    VulTaskImpl vulTask;

    public WebSocketHijackingCallback(VulTaskImpl vulTask){
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
            "[WebSocketHijackingCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (BurpReqRespTools.getStatus(requestResponse) == 101){
            message = "WebSocketHijacking";
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