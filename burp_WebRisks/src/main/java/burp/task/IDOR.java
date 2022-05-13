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
import java.util.Locale;

public class IDOR extends VulTaskImpl {

    public IDOR(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 未授权访问
         * 检测逻辑
         * 1、删除cookie发起请求
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }

        //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
        // 只测试原本有cookie的请求
        List<String> new_headers1 = new ArrayList<String>();
        boolean hasCookie = false;
        for (String header :
                request_header_list) {
            //删除cookie
            String key = BurpExtender.cookie.split(":")[0];
            if (header.toLowerCase(Locale.ROOT).startsWith(key.toLowerCase(Locale.ROOT))) {
                hasCookie = true;
            }else {
                new_headers1.add(header);
            }
        }
        // 请求没有cookie,则不测试
        if (!hasCookie){
            return null;
        }
        request_header_list = new_headers1;
        //新的请求包
        okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new IDORCallback(this));

        return result;
    }
}

class IDORCallback implements Callback {

    VulTaskImpl vulTask;

    public IDORCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[IDORCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
//        vulTask.callbacks.printOutput("IDORCallback\n" + call.request());
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody)) {
                vulTask.message = "IDOR";
                vulTask.log(call);
            }

        }
    }
}