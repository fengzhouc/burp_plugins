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

/***
 *
 * Spring Boot Actuator
 *
 *
 *
 *
 * References:
 *  - http://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready-endpoints
 *
 *
 */
public class SpringBootActuator extends VulTaskImpl {
    private static final List<String> SPRINGBOOT_ACTUATOR_PATHS = Arrays.asList(
            "/health",
            "/manager/health",
            "/actuator",
            "/actuator/jolokia/list",
            "/jolokia/list",
            "/env"
    );

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SpringBootActuator(requestResponse);
    }
    private SpringBootActuator(IHttpRequestResponse requestResponse) {
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
                    SPRINGBOOT_ACTUATOR_PATHS) {
                String url = String.format("%s%s", BurpReqRespTools.getRootUrl(requestResponse), api);
                okHttpRequester.send(
                    url, 
                    "GET", 
                    BurpReqRespTools.getReqHeaders(requestResponse), 
                    null, 
                    null, 
                    null, 
                    new SpringBootActuatorCallback(this));
            }
            TaskManager.vulsChecked.add(String.format("burp.task.api.SpringBootActuator_%s_%s",BurpReqRespTools.getHost(requestResponse),BurpReqRespTools.getPort(requestResponse))); //添加检测标记
        }
    }
}

class SpringBootActuatorCallback implements Callback {

    VulTaskImpl vulTask;
    private static final List<String> GREP_STRINGS = Arrays.asList(
            "{\"status\":\"UP\"}",
            "{\"_links\":",
            "org.spring",
            "java.vendor"
    );

    public SpringBootActuatorCallback(VulTaskImpl vulTask){
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
            SpringBootActuator.class.getSimpleName(),
             "onFailure", 
             "[SpringBootActuatorCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            for (String b:
                 GREP_STRINGS) {
                if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains(b)) {
                    message = "SpringBootActuator";
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
            SpringBootActuator.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/SpringBootActuator.bbm")));
    }
}