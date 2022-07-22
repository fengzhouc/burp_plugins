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
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class Https extends VulTaskImpl {
    private static VulTaskImpl instance = null;
    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        if (instance == null){
            instance = new Https(helpers, callbacks, log);
        }
        return instance;
    }

    private Https(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            String protocol = iHttpService.getProtocol();
            if (protocol.toLowerCase(Locale.ROOT).startsWith("https")){
                message = "use https";
            }
            // 检查是否同时开启http/https
            this.url = "http://" + iHttpService.getHost() + ":80" + path;
            List<String> new_header = new ArrayList<>();
            for (String header :
                    request_header_list) {
                if (!header.contains("Host")){
                    new_header.add(header);
                }
            }
            new_header.add("Host: " + iHttpService.getHost() + ":80");
            request_header_list = new_header;

            okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new HttpsCallback(this));
        }
    }
}

class HttpsCallback implements Callback {

    VulTaskImpl vulTask;

    public HttpsCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[HttpsCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            if (!vulTask.message.equalsIgnoreCase("")) {
                vulTask.message += ", and open http";
            } else {
                vulTask.message = "open http";
            }
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            vulTask.log(call);
        }
    }
}