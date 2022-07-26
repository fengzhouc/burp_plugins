package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Json3rd extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new Json3rd(helpers, callbacks, log);
    }
    private Json3rd(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、注入引号，造成服务器异常，返回堆栈信息
         * 2、检查堆栈信息，看是否有关键字，如fastjson等
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            //如果有body参数，需要多body参数进行测试
            if (request_body_str.length() > 0){
                if (contentYtpe.contains("application/json")){
                    String is = "'\""; //json格式的使用转义后的，避免json格式不正确
                    String req_body = createJsonBody(request_body_str, is);
                    //新的请求包
                    okHttpRequester.send(url, method, request_header_list, query, req_body, contentYtpe, new Json3rdCallback(this));
                }
            }
        }
    }

}

class Json3rdCallback implements Callback {

    VulTaskImpl vulTask;

    public Json3rdCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[Json3rdCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        // 检查响应中是否存在flag
        if (vulTask.ok_respBody.contains("fastjson")) {
            vulTask.message = "fastjson";
            vulTask.log(call);
        }else if (vulTask.ok_respBody.contains("jackson")) {
            vulTask.message = "jackson";
            vulTask.log(call);
        }else if (vulTask.ok_respBody.contains("gson")) {
            vulTask.message = "gson";
            vulTask.log(call);
        }
    }
}