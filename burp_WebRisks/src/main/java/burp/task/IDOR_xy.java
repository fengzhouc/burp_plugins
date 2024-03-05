package burp.task;

import burp.*;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class IDOR_xy extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new IDOR_xy(helpers, callbacks, log);
    }
    private IDOR_xy(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 横向越权
         * 检测逻辑
         * 1、设置别的用户cookie
         * 2、填充cookie重放，比对响应
         * */
        // 没有设置越权测试的cookie则不测试
        if (!BurpExtender.cookie.equalsIgnoreCase("Cookie: xxx")){
            // 后缀检查，静态资源不做测试
            List<String> add = new ArrayList<String>();
            add.add(".js");
            if (!isStaticSource(path, add)){
                //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
                // 只测试原本有cookie的请求
                List<String> new_headers1 = new ArrayList<String>();
                for (String header :
                        request_header_list) {
                    //替换cookie
                    String[] auth = BurpExtender.cookie.split(":");
                    String key = auth[0];
                    String value = auth[1];
                    if (header.toLowerCase(Locale.ROOT).startsWith(key.toLowerCase(Locale.ROOT))) {
                        header = key + ":" + value;
                    }
                    new_headers1.add(header);
                }
                //新的请求包
                okHttpRequester.send(url, method, new_headers1, query, request_body_str, contentYtpe, new IDORxyCallback(this));
            }
        }
    }
}

class IDORxyCallback implements Callback {

    VulTaskImpl vulTask;

    public IDORxyCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[IDORxyCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody)) {
                vulTask.message = "IDOR_xy";
                vulTask.log(call);
            }

        }
    }
}