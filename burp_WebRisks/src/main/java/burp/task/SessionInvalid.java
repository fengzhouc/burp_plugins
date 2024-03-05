package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.impl.VulTaskImpl;
import burp.util.CommonMess;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SessionInvalid extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SessionInvalid(helpers, callbacks, log);
    }
    private SessionInvalid(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 登出后历史会话是否还有效
         * 检测逻辑
         * 1.保存一个需要登陆后才能访问的请求（IDOR中保存）
         * 2.检测到是登出接口，则重请求历史请求是否可以请求成果
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            // 只有登出后才会进行重放，这里需要持续增加登出的接口url
            if (url.endsWith("/logout")
                || url.endsWith("/remove")) {
                IHttpRequestResponse iHttpRequestResponse = CommonMess.authMessageInfo;
                if (iHttpRequestResponse != null){
                    this.init(iHttpRequestResponse); //将历史的请求进行初始化进行重放验证
                    //新的请求包
                    okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SessionInvalidCallback(this));
                }
            }
        }
    }
}

class SessionInvalidCallback implements Callback {

    VulTaskImpl vulTask;

    public SessionInvalidCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SeesionInvalidCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody)) {
                vulTask.message = "SeesionInvalid";
                vulTask.log(call);
            }

        }
    }
}