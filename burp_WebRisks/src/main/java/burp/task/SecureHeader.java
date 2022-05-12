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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecureHeader extends VulTaskImpl {

    public SecureHeader(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }

        okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SecureHeaderCallback(this));

        return result;
    }
}

class SecureHeaderCallback implements Callback {

    VulTaskImpl vulTask;

    public SecureHeaderCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SecureHeaderCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        //检查响应头
//        headers.add("Strict-Transport-Securit"); // max-age=31536000;includeSubDomains;preload
//        headers.add("X-Frame-Options"); // allow-from 'url'
//        headers.add("X-XSS-Protection"); // 1;mode=block
//        headers.add("X-Content-Type-Options"); // nosniff
//        headers.add("Content-Security-Policy");
        if (response.isSuccessful()){
            String frame = response.header("X-Frame-Options");
            if (frame == null){
                vulTask.message = "without X-Frame-Options";
                vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
                vulTask.log();
            }
        }
    }
}