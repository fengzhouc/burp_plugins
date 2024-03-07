package com.alumm0x.task.api;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SwaggerApi extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SwaggerApi(requestResponse);
    }
    private SwaggerApi(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            // 构造url
            for (String api :
                    SourceLoader.loadSources("/payloads/SwaggerApi.bbm")) {
                String url = String.format("%s://%s:%d%s", BurpReqRespTools.getProtocol(requestResponse), BurpReqRespTools.getHost(requestResponse), BurpReqRespTools.getPort(requestResponse), api);
                okHttpRequester.send(
                    url, 
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getReqHeaders(requestResponse), 
                    BurpReqRespTools.getQuery(requestResponse), 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new LiferayAPICallback(this));
            }
            TaskManager.vulsChecked.add(String.format("burp.task.api.SwaggerApi_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class SwaggerApiCallback implements Callback {

    VulTaskImpl vulTask;

    public SwaggerApiCallback(VulTaskImpl vulTask){
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
            SwaggerApi.class.getSimpleName(),
            "onFailure", 
            "[SwaggerApiCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("<title>Swagge")) {
                message = "SwaggerApi";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            SwaggerApi.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/SwaggerApi.bbm")));
    }
}