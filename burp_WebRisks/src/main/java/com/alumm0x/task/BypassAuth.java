package com.alumm0x.task;

import burp.*;
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

public class BypassAuth extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new BypassAuth(requestResponse);
    }

    private BypassAuth(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 绕过url鉴权
         */
        //条件：403/401禁止访问的才需要测试
        int status = BurpReqRespTools.getStatus(requestResponse);
        if (status == 401 || status == 403){
            // 后缀检查，静态资源不做测试
            List<String> add = new ArrayList<String>();
            add.add(".js");
            if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
                List<String> bypass_str = SourceLoader.loadSources("/payloads/BypassAuth.bbm");

                // 将path拆解
                List<String> bypass_path = createPath(bypass_str, BurpReqRespTools.getUrlPath(requestResponse));
                bypass_str.add("\n#TestUrl\n"); // 记录测试的url
                StringBuilder stringBuilder = new StringBuilder();
                for (String p :
                        bypass_path) {
                    stringBuilder.append("// ").append(p).append("\n");
                }
                bypass_str.add(stringBuilder.toString()); // 记录测试的url

                for (String bypass : bypass_path) {
                    //url有参数
                    String url = BurpReqRespTools.getRootUrl(requestResponse) + bypass;
                    okHttpRequester.send(
                        url, 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        BurpReqRespTools.getQuery(requestResponse), 
                        new String(BurpReqRespTools.getReqBody(requestResponse)), 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new BypassAuthCallback(this));
                }
            }
        }
    }

    private List<String> createPath(List<String> bypass_str, String urlpath){
        // 将path拆解
        String[] paths = urlpath.split("/");
        List<String> bypass_path = new ArrayList<String>();
        // 添加bypass，如:/api/test
        // /api;/test
        // /api/xx;/../test
        for (String str : bypass_str) {
            for (int i = 0; i< paths.length; i++){
                if (!"".equalsIgnoreCase(paths[i])) { //为空则跳过，split分割字符串，分割符头尾会出现空字符
                    String bypassStr = paths[i] + str;
                    StringBuilder sb = new StringBuilder();
                    for (int j = 0; j < paths.length; j++) {
                        if (!"".equalsIgnoreCase(paths[j])) { //为空则跳过，split分割字符串，分割符头尾会出现空字符
                            if (i == j) {
                                sb.append("/").append(bypassStr);
                                continue;
                            }
                            sb.append("/").append(paths[j]);
                        }
                    }
                    bypass_path.add(sb.toString());
                }
            }
        }
        return bypass_path;
    }
}

class BypassAuthCallback implements Callback {

    VulTaskImpl vulTask;

    public BypassAuthCallback(VulTaskImpl vulTask){
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
             "[BypassAuthCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        //如果状态码200,然后响应内容不同，则存在url鉴权绕过
        if (response.isSuccessful()) {
            message = "BypassAuth";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            message, 
            String.join("/n", SourceLoader.loadSources("/payloads/BypassAuth.bbm")));
    }
}
