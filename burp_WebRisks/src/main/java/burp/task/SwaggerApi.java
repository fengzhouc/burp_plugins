package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SwaggerApi extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SwaggerApi(helpers, callbacks, log);
    }
    private SwaggerApi(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            payloads = loadPayloads("/payloads/SwaggerApi.bbm");

            // 构造url
            for (String api :
                    payloads.split("\n")) {
                String url = String.format("%s://%s:%d%s", iHttpService.getProtocol(), iHttpService.getHost(), iHttpService.getPort(), api);
                okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SwaggerApiCallback(this));
            }
            BurpExtender.vulsChecked.add("burp.task.SwaggerApi" + host + iHttpService.getPort()); //添加检测标记
        }
    }
}

class SwaggerApiCallback implements Callback {

    VulTaskImpl vulTask;

    public SwaggerApiCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SwaggerApiCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            if (vulTask.ok_respBody.contains("<title>Swagge"))
            vulTask.message = "SwaggerApi";
            vulTask.log(call);
        }
    }
}