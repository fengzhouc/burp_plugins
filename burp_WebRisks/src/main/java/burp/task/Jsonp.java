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
import java.util.List;

public class Jsonp extends VulTaskImpl {

    public Jsonp(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、无字段则添加字段在测试
         * */
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path, null)){
            return null;
        }
        //jsonp只检测get请求
        if (!method.equalsIgnoreCase("get")){
            return null;
        }

        //1.请求的url中含Jsonp敏感参数
        if (query.contains("callback=")
                || query.contains("cb=")
                || query.contains("jsonp")
                || query.contains("json=")
                || query.contains("call="))
        {
            logAdd(messageInfo, host, path, method, status, "Jsonp", payloads);
        }

        //2.url不含敏感参数,添加参数测试
        else {
            String new_query = "";
            //url有参数
            if (!query.equals("")) {
                new_query = "call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert&" + query;
            } else {//url无参数
                new_query = "call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert";
            }
            //新的请求包
            okHttpRequester.send(url, method, request_header_list, new_query, request_body_str, contentYtpe, new JsonpCallback(this));
        }

        return result;
    }
}

class JsonpCallback implements Callback {

    VulTaskImpl vulTask;

    public JsonpCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[JsonpCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.ok_respBody.contains("qwert")) {
                vulTask.message = "Jsonp";
                vulTask.log();
            }

        }
    }
}
