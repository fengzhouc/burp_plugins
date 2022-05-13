package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.HttpRequestResponseFactory;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SqlInject extends VulTaskImpl {

    public SqlInject(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */
        String injectStr = helpers.urlEncode("'\"\\\"");

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }
        payloads = loadPayloads("/payloads/SqlInject.bbm");
        //反射型只测查询参数
        if (query != null)
        {
            String new_query = createFormBody(query, injectStr);
            //新的请求包
            okHttpRequester.send(url, method, request_header_list, new_query, request_body_str, contentYtpe, new SqlInjectCallback(this));
        }
        //如果有body参数，需要多body参数进行测试
        if (request_body_str.length() > 0){
            String contentype = "";
            if (contentYtpe.contains("application/json")){
                contentype = "json";
            }else if (contentYtpe.contains("application/x-www-form-urlencoded")){
                contentype = "form";
            }
            String req_body = request_body_str;
            switch (contentype){
                case "json":
                    String is = "\\\'\\\""; //json格式的使用转义后的，避免json格式不正确
                    req_body = createJsonBody(request_body_str, is);
                    break;
                case "form":
                    req_body = createFormBody(request_body_str, injectStr);
                    break;
            }
            //新的请求包
            okHttpRequester.send(url, method, request_header_list, query, req_body, contentYtpe, new SqlInjectCallback(this));
        }
        return result;
    }

}

class SqlInjectCallback implements Callback {

    VulTaskImpl vulTask;

    public SqlInjectCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SqlInjectCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        // 检查响应中是否存在flag
        // TODO 关键字是否全
        if (vulTask.ok_respBody.contains("SQL syntax")) {
            vulTask.message = "SqlInject";
            vulTask.log(call);
        }
    }
}