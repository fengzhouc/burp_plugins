package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;
import burp.util.HeaderTools;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BypassAuthXFF extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new BypassAuthXFF(helpers, callbacks, log);
    }

    private BypassAuthXFF(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 绕过xff绕过本地限制
         */
        //条件：403禁止访问的才需要测试
        if (status == 403){
            // 后缀检查，静态资源不做测试
            List<String> add = new ArrayList<String>();
            add.add(".js");
            if (!isStaticSource(path, add)){
                List<String> new_headers1 = new ArrayList<>();
                new_headers1.addAll(request_header_list);
                //添加xff的头部
                new_headers1.addAll(HeaderTools.setXFF());

                okHttpRequester.send(url, method, new_headers1, query, request_body_str, contentYtpe, new BypassAuthXFFCallback(this));
            }
        }
    }
}

class BypassAuthXFFCallback implements Callback {

    VulTaskImpl vulTask;

    public BypassAuthXFFCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[BypassAuthXFFCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        //如果状态码200，则存在xff绕过
        if (response.isSuccessful()) {
            vulTask.message = "BypassAuth-XFF";
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            vulTask.log(call);
        }
    }
}
