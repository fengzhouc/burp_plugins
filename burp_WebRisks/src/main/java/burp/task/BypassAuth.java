package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.HttpRequestResponseFactory;
import burp.util.OkHttpRequester;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class BypassAuth extends VulTaskImpl {
    private static VulTaskImpl instance = null;
    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        if (instance == null){
            instance = new BypassAuth(helpers, callbacks, log);
        }
        return instance;
    }

    private BypassAuth(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 绕过url鉴权
         */
        //条件：403/401禁止访问的才需要测试
        if (status == 401 || status == 403){
            // 后缀检查，静态资源不做测试
            List<String> add = new ArrayList<String>();
            add.add(".js");
            if (!isStaticSource(path, add)){
                payloads = loadPayloads("/payloads/BypassAuth.bbm");
                List<String> bypass_str = new ArrayList<String>();
                Collections.addAll(bypass_str, payloads.split("\n"));

                // 将path拆解
                List<String> bypass_path = createPath(bypass_str, path);

                for (String bypass :
                        bypass_path) {
                    //url有参数
                    this.url = this.url.replace(path, bypass);
                    okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new BypassAuthCallback(this));
                }
            }
        }
    }

    private List<String> createPath(List<String> bypass_str, String urlpath){
        // 将path拆解
        String[] paths = urlpath.split("/");
        List<String> bypass_path = new ArrayList<String>();
        // 添加bypass，如:/api/test
        // /api;/test
        // /api/xx;/../test
        for (String str : bypass_str) {
            for (int i = 0; i< paths.length; i++){
                String bypassStr = paths[i] + str;
                StringBuilder sb = new StringBuilder();
                for (int j = 0; j< paths.length; j++) {
                    if (i == j){
                        sb.append("/").append(bypassStr);
                        continue;
                    }
                    sb.append("/").append(paths[j]);
                }
                bypass_path.add(sb.toString());
            }
        }
        return bypass_path;
    }
}

class BypassAuthCallback implements Callback {

    VulTaskImpl vulTask;

    public BypassAuthCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[BypassAuthCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        //如果状态码200,然后响应内容不同，则存在url鉴权绕过
        if (response.isSuccessful()) {
            vulTask.message = "BypassAuth";
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            vulTask.log(call);
        }
    }
}
