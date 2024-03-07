package com.alumm0x.task.config;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Https extends VulTaskImpl {

    String message = null;

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Https(requestResponse);
    }

    private Https(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            String protocol = BurpReqRespTools.getProtocol(requestResponse);
            if (protocol.toLowerCase(Locale.ROOT).startsWith("https")){
                message = "use https";
            }
            // 检查是否同时开启http/https
            List<String> new_headers = new ArrayList<>();
            for (String header :
                    BurpReqRespTools.getReqHeaders(requestResponse)) {
                if (!header.contains("Host")){
                    new_headers.add(header);
                }
            }
            new_headers.add("Host: " + BurpReqRespTools.getHost(requestResponse) + ":80");
            String url = "http://" + BurpReqRespTools.getHost(requestResponse) + BurpReqRespTools.getUrlPath(requestResponse);
            // 检测80端口
            okHttpRequester.send(
                url, 
                BurpReqRespTools.getMethod(requestResponse), 
                new_headers, 
                BurpReqRespTools.getQuery(requestResponse), 
                new String(BurpReqRespTools.getReqBody(requestResponse)), 
                BurpReqRespTools.getContentType(requestResponse), 
                new HttpsCallback(this));
            TaskManager.vulsChecked.add(String.format("burp.task.api.Https_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class HttpsCallback implements Callback {

    VulTaskImpl vulTask;

    public HttpsCallback(VulTaskImpl vulTask){
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
            Https.class.getSimpleName(),
            "onFailure", 
            "[HttpsCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            if (!((Https)vulTask).message.equalsIgnoreCase("")) {
                ((Https)vulTask).message += ", and open http";
            } else {
                ((Https)vulTask).message = "open http";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            Https.class.getSimpleName(),
            ((Https)vulTask).message, 
            null);
    }
}