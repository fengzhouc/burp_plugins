package com.alumm0x.task;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.JsonTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SqlInject extends VulTaskImpl {
    public boolean isDeep = false;
    private String injectStr;
    private String injectJsonStr;

    public void setInjectStr(String injectStr) {
        this.injectStr = injectStr;
    }

    public void setInjectJsonStr(String injectJsonStr) {
        this.injectJsonStr = injectJsonStr;
    }


    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SqlInject(requestResponse);
    }
    private SqlInject(IHttpRequestResponse requestResponse) {
        super(requestResponse);
        injectStr = BurpExtender.helpers.urlEncode("'\""); // '"
        injectJsonStr = BurpExtender.helpers.urlEncode("\\\'\\\""); // \'\",json格式的使用转义后的，避免json格式不正确
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //反射型只测查询参数
            String query = BurpReqRespTools.getQuery(requestResponse);
            if (query != null)
            {
                String new_query = JsonTools.createFormBody(query, injectStr);
                //新的请求包
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getReqHeaders(requestResponse), 
                    new_query, 
                    new String(BurpReqRespTools.getReqBody(requestResponse)), 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new SqlInjectCallback(this));
            }
            //如果有body参数，需要多body参数进行测试
            String request_body_str = new String(BurpReqRespTools.getReqBody(requestResponse));
            if (request_body_str.length() > 0){
                String contentYtpe = ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-type");
                String contentype = "";
                if (contentYtpe.contains("application/json")){
                    contentype = "json";
                }else if (contentYtpe.contains("application/x-www-form-urlencoded")){
                    contentype = "form";
                }
                String req_body = request_body_str;
                switch (contentype){
                    case "json":
                        req_body = JsonTools.createJsonBody(request_body_str, injectJsonStr);
                        break;
                    case "form":
                        req_body = JsonTools.createFormBody(request_body_str, injectStr);
                        break;
                }
                //新的请求包
                okHttpRequester.send(
                    BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                    BurpReqRespTools.getMethod(requestResponse), 
                    BurpReqRespTools.getReqHeaders(requestResponse), 
                    BurpReqRespTools.getQuery(requestResponse), 
                    req_body, 
                    BurpReqRespTools.getContentType(requestResponse), 
                    new SqlInjectCallback(this));
            }
        }
    }

}

class SqlInjectCallback implements Callback {

    VulTaskImpl vulTask;

    public SqlInjectCallback(VulTaskImpl vulTask){
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
            SqlInject.class.getSimpleName(),
            "onFailure", 
            "[SqlInjectCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        // 如果是我设计操作数据的业务，主要也就增删改查
        // 1.增，会反馈成功与否，前端做提醒
        // 2.删，会反馈成功与否，前端做提醒
        // 3.改，会反馈成功与否，前端做提醒，或者是返回修改后的对象信息
        // 4.查，会反馈成功与否，前端做提醒
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        // 如果400就是客户端错误了，大概率异常数据影响请求结构了，不深入检测
        if (response.code() != 400) {
            // 重放的请求响应跟原始的不一样，才进一步判断，两种情况
            // 1.要么参数会呈现在响应中
            // 2.有异常信息，或者是因为异常导致返回异常处理的响应
            if (!(BurpReqRespTools.getStatus(requestResponse) == BurpReqRespTools.getStatus(vulTask.requestResponse)
                && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse)))) {
                // 检查响应中是否存在sql报错信息
                String respBody = new String(BurpReqRespTools.getRespBody(requestResponse));
                // TODO 关键字是否全
                if (respBody.contains("SQL syntax")) {
                    message = "SqlInject, has Error";
                } else {
                    // 避免死循环，只深入检测一次
                    if (!((SqlInject)vulTask).isDeep) {
                        // 布尔false的进行三次，无引号/单引号/双引号
                        Map<String, String> injects = new HashMap<>();
                        injects.put(" or 1=2", "or 1=2");
                        injects.put("'or'1'='2", "\\'or\\\'1\\\'=\\\'2");
                        injects.put("\"or\"1\"=\"2", "\\\"or\\\"1\\\"=\\\"2");
                        for (Map.Entry<String, String> entry : injects.entrySet()) {
                            String form = BurpExtender.helpers.urlEncode(entry.getKey());
                            String json = BurpExtender.helpers.urlEncode(entry.getValue());
                            // 不存在爆破信息，则尝试下布尔型，如果跟源响应一致，则不存在问题
                            SqlInject sqlInject = (SqlInject) SqlInject.getInstance(vulTask.requestResponse);
                            sqlInject.setInjectStr(form);
                            sqlInject.setInjectJsonStr(json);
                            sqlInject.isDeep = true; // 避免死循环
                            sqlInject.start();
                        }
                    }
                }
            }else {
                // 布尔检测的预期是响应跟源请求是不一样的，走到这条分支，已经是前面那个条件判断响应与源响应一样了，所以大概率是存在风险的
                message = "SqlInject Boolean";
            }
            // 布尔false的异常数据都响应一样的话，是啥情况呢？
            // 1.统一的返回数据，不好检测了
            // 2.大概率跟数据库无关了
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            SqlInject.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/SqlInject.bbm")));
    }
}