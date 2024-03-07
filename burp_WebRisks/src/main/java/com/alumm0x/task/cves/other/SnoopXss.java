package com.alumm0x.task.cves.other;

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
import java.util.Arrays;
import java.util.List;

/**
 * This module tries to identify snoop resources to identify
 * possible information disclosure vulnerabilities and XSS issues
 *
 */
public class SnoopXss extends VulTaskImpl {

    private static final String XSS_PAYLOAD = "<h1>WebRisks";

    private static final List<String> SNOOP_PATHS = Arrays.asList(
            "/snoop.jsp?" + XSS_PAYLOAD,
            "/examples/jsp/snp/snoop.jsp?" + XSS_PAYLOAD,
            "/examples/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/j2ee/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/jsp-examples/snp/snoop.jsp?" + XSS_PAYLOAD
    );

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SnoopXss(requestResponse);
    }
    private SnoopXss(IHttpRequestResponse requestResponse) {
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
                    SNOOP_PATHS) {
                String url = String.format("%s%s", BurpReqRespTools.getRootUrl(requestResponse), api);
                okHttpRequester.send(
                    url, 
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getReqHeaders(requestResponse), 
                    BurpReqRespTools.getQuery(requestResponse), 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new SnoopXssCallback(this));
            }
            TaskManager.vulsChecked.add(String.format("burp.vuls.other.SnoopXss_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class SnoopXssCallback implements Callback {

    VulTaskImpl vulTask;
    // JSP snoop page</TITLE>
    // <TITLE>JSP snoop page</TITLE>
    // <TITLE>JBossEAP6.0 JSP snoop page</TITLE>
    // Path translated:
    private static final String GREP_STRING = "Path translated";

    public SnoopXssCallback(VulTaskImpl vulTask){
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
            SnoopXss.class.getSimpleName(),
            "onFailure", 
            "[SnoopXssCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            // 检查响应体是否有内容
            String respBody = new String(BurpReqRespTools.getRespBody(requestResponse));
            if (respBody.contains(GREP_STRING)) {
                message = "SnoopXss";
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            SnoopXss.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/SnoopXss.bbm")));
    }
}