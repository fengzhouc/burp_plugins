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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BypassAuthXFF extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new BypassAuthXFF(requestResponse);
    }

    private BypassAuthXFF(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 绕过xff绕过本地限制
         */
        //条件：403禁止访问的才需要测试
        if (BurpReqRespTools.getStatus(requestResponse) == 403){
            // 后缀检查，静态资源不做测试
            List<String> add = new ArrayList<String>();
            add.add(".js");
            if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
                List<String> new_headers = new ArrayList<>();
                new_headers.addAll(BurpReqRespTools.getReqHeaders(requestResponse));
                //添加xff的头部
                new_headers.addAll(HeaderTools.setXFF());

                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    new_headers, 
                    BurpReqRespTools.getQuery(requestResponse), 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new BypassAuthXFFCallback(this));
            }
        }
    }
}

class BypassAuthXFFCallback implements Callback {

    VulTaskImpl vulTask;

    public BypassAuthXFFCallback(VulTaskImpl vulTask){
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
            "[BypassAuthXFFCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        //如果状态码200，则存在xff绕过
        if (response.isSuccessful()) {
            message = "BypassAuth-XFF";
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
