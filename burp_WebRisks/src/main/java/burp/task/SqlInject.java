package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.HttpRequestResponseFactory;
import burp.util.Requester;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
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


    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SqlInject(helpers, callbacks, log);
    }
    private SqlInject(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
        injectStr = helpers.urlEncode("'\""); // '"
        injectJsonStr = helpers.urlEncode("\\\'\\\""); // \'\",json格式的使用转义后的，避免json格式不正确
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
        if (!isStaticSource(path, add)){
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
                        req_body = createJsonBody(request_body_str, injectJsonStr);
                        break;
                    case "form":
                        req_body = createFormBody(request_body_str, injectStr);
                        break;
                }
                //新的请求包
                okHttpRequester.send(url, method, request_header_list, query, req_body, contentYtpe, new SqlInjectCallback(this));
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
        vulTask.callbacks.printError("[SqlInjectCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        // 如果是我设计操作数据的业务，主要也就增删改查
        // 1.增，会反馈成功与否，前端做提醒
        // 2.删，会反馈成功与否，前端做提醒
        // 3.改，会反馈成功与否，前端做提醒，或者是返回修改后的对象信息
        // 4.查，会反馈成功与否，前端做提醒

        // 如果400就是客户端错误了，大概率异常数据影响请求结构了，不深入检测
        if (response.code() != 400) {
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            // 重放的请求响应跟原始的不一样，才进一步判断，两种情况
            // 1.要么参数会呈现在响应中
            // 2.有异常信息，或者是因为异常导致返回异常处理的响应
            if (!(vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody))) {
                // 检查响应中是否存在sql报错信息
                // TODO 关键字是否全
                if (vulTask.ok_respBody.contains("SQL syntax")) {
                    vulTask.message = "SqlInject, has Error";
                    vulTask.log(call);
                } else {
                    // 避免死循环，只深入检测一次
                    if (!((SqlInject)vulTask).isDeep) {
                        // 布尔false的进行三次，无引号/单引号/双引号
                        Map<String, String> injects = new HashMap<>();
                        injects.put(" or 1=2", "or 1=2");
                        injects.put("'or'1'='2", "\\'or\\\'1\\\'=\\\'2");
                        injects.put("\"or\"1\"=\"2", "\\\"or\\\"1\\\"=\\\"2");
                        for (Map.Entry<String, String> entry : injects.entrySet()) {
                            String form = vulTask.helpers.urlEncode(entry.getKey());
                            String json = vulTask.helpers.urlEncode(entry.getValue());
                            // 不存在爆破信息，则尝试下布尔型，如果跟源响应一致，则不存在问题
                            SqlInject sqlInject = (SqlInject) SqlInject.getInstance(vulTask.helpers, vulTask.callbacks, vulTask.log);
                            sqlInject.setInjectStr(form);
                            sqlInject.setInjectJsonStr(json);
                            sqlInject.init(vulTask.messageInfo);
                            sqlInject.isDeep = true; // 避免死循环
                            sqlInject.start();
                        }
                    }else {
                        // 布尔检测的预期是响应跟源请求是不一样的，走到这条分支，已经是前面那个条件判断响应与源响应一样了，所以大概率是存在风险的
                        vulTask.message = "SqlInject Boolean";
                        vulTask.log(call);
                    }
                }
            }
            // 布尔false的异常数据都响应一样的话，是啥情况呢？
            // 1.统一的返回数据，不好检测了
            // 2.大概率跟数据库无关了
        }
    }
}