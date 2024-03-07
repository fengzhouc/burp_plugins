package com.alumm0x.vuls.shiro;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ShiroUse extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse) {
        return new ShiroUse(requestResponse);
    }
    private ShiroUse(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    /**
     * 这个只是看下是否使用了shiro，并检测是否使用默认密钥
     */
    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、确认使用shiro
         *  添加cookie：rememberMe=1，检车是否返回cookie：rememberMe=deleteMe
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            List<String> new_headers1 = new ArrayList<>();
            String cookie = "rememberMe=1";
            boolean hasCookie = false;
            //新请求修改origin
            for (String header : BurpReqRespTools.getReqHeaders(requestResponse)) {
                if (header.toLowerCase(Locale.ROOT).startsWith("Cookie".toLowerCase(Locale.ROOT))) {
                    new_headers1.add(header + ";" + cookie);
                    hasCookie = true;
                    continue;
                }
                new_headers1.add(header);
            }
            if (!hasCookie){
                new_headers1.add("Cookie: " + cookie);
            }
            
            okHttpRequester.send(
                    BurpReqRespTools.getRootUrl(requestResponse), 
                    "GET", 
                    new_headers1, 
                    null, 
                    null, 
                    null, 
                    new ShiroUseCallback(this));
            TaskManager.vulsChecked.add(String.format("burp.vuls.shiro.ShiroUse_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class ShiroUseCallback implements Callback {

    VulTaskImpl vulTask;

    public ShiroUseCallback(VulTaskImpl vulTask){
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
            "[ShiroUseCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        // 检查响应体是否有内容
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        String setCookie = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
        if (setCookie != null && setCookie.contains("=deleteMe")) {
            // TODO 如果使用了则看下是否用了默认key
            message = "ShiroUse";
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