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

public class MethodFuck extends VulTaskImpl {

    public MethodFuck(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、尝试其他method是否可以请求通，有可能是同一个api不同的method，主要是get/post/put/patch
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }
        List<String> methods = new ArrayList<>();
        methods.add("GET");
        methods.add("POST");
        methods.add("PUT");
        methods.add("PATCH");

        if (methods.contains(method)) {
            methods.remove(method); //删除已有的，检测其他的
            for (String method :
                    methods) {
                //新的请求包
                okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new MethodFuckCallback(this));
            }
        }
        return result;
    }
}

class MethodFuckCallback implements Callback {

    VulTaskImpl vulTask;

    public MethodFuckCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[MethodFuckCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        if (vulTask.ok_code != 404
                && vulTask.ok_code != 405
                && vulTask.ok_code != 400
                && vulTask.ok_code != 500
                && vulTask.ok_code != 403) {
            vulTask.message = "MethodFuck-" + call.request().method();
            vulTask.log(call);
        }
    }
}