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

public class SecureCookie extends VulTaskImpl {
    private static VulTaskImpl instance = null;
    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        if (instance == null){
            instance = new SecureCookie(helpers, callbacks, log);
        }
        return instance;
    }

    private SecureCookie(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SecureCookieCallback(this));
        }
    }
}

class SecureCookieCallback implements Callback {

    VulTaskImpl vulTask;

    public SecureCookieCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SecureCookieCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        //检查响应头Location
        if (response.isSuccessful()){
            String setCookie = response.header("Set-Cookie");
            if (setCookie != null && (!setCookie.toLowerCase(Locale.ROOT).contains("httponly") || !setCookie.toLowerCase(Locale.ROOT).contains("secure"))){
                vulTask.message = "without httponly or secure";
            }
            // 默认domain为本域，如果设置了则判断下是否为子域
            if (setCookie.toLowerCase(Locale.ROOT).contains("domain=")){
                Pattern p = Pattern.compile("domain=(.*?);");
                Matcher matcher = p.matcher(setCookie);
                if (matcher.find()){
                    String d = matcher.group(1);
                    if (!vulTask.host.toLowerCase(Locale.ROOT).endsWith(d.toLowerCase(Locale.ROOT))){
                        vulTask.message += ", domain no secure";
                    }
                }
            }
        }
        if (!vulTask.message.equalsIgnoreCase("")){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            vulTask.log(call);
        }
    }
}