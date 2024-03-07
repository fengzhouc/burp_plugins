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
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LiferayAPI extends VulTaskImpl {
    private final static List<String> PATHS = Arrays.asList(
            "/api/jsonws",  //JSON，https://help.liferay.com/hc/en-us/articles/360018151631-JSON-Web-Services，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
            "/api/axis",    //SOAP，https://help.liferay.com/hc/en-us/articles/360017872492-SOAP-Web-Services，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
            "/api/liferay", //Liferay tunnel servlet，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
            "/webdav"       //WebDAV servlet，https://help.liferay.com/hc/en-us/articles/360018172711-Desktop-Access-to-Documents-and-Media，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
    );

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new LiferayAPI(requestResponse);
    }
    private LiferayAPI(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){

            // 构造url
            for (String api : PATHS) {
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
            TaskManager.vulsChecked.add(String.format("burp.task.api.LiferayAPI_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class LiferayAPICallback implements Callback {

    VulTaskImpl vulTask;
    private final static List<Pattern> PATTERNS = Arrays.asList(
            Pattern.compile(".*<title>json-web-services-api<\\/title>.*", Pattern.DOTALL),
            Pattern.compile(".*<h2>And now\\.\\.\\. Some Services<\\/h2>.*", Pattern.DOTALL),
            Pattern.compile(".*Internal Server Error.*An error occurred while accessing the requested resource\\..*", Pattern.DOTALL)
    );

    public LiferayAPICallback(VulTaskImpl vulTask){
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
            "[LiferayAPICallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            for (Pattern p :
                    PATTERNS) {
                Matcher m = p.matcher(new String(BurpReqRespTools.getRespBody(requestResponse)));
                if (m.find()){
                    message = "LiferayAPI";
                    break;
                }
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
            String.join("\n", SourceLoader.loadSources("/payloads/LiferayAPI.bbm")));
    }
}