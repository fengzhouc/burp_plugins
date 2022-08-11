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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class Csrf extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new Csrf(helpers, callbacks, log);
    }
    private Csrf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、Csrf-form表单
         *   （1）检查content为form表单
         *   （2）删除token请求头重放，看是否响应跟原响应一致
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (check(request_header_list, "Cookie") != null){
                //要包含centen-type,且为form表单，这里就会吧get排除掉了
                String ct = check(request_header_list, "Content-Type");
                if (ct != null && ct.contains("application/x-www-form-urlencoded")){
                    List<String> new_headers1 = new ArrayList<>();
                    //新请求修改origin
                    for (String header : request_header_list) {
                        // 剔除掉csrf头部
                        if (HeaderTools.inNormal(header.split(":")[0])) {
                            if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                                new_headers1.add(header);
                            }
                        }
                    }
                    okHttpRequester.send(url, method, new_headers1, query, request_body_str, contentYtpe, new CsrfCallback(this));
                }
            }
        }
    }
}

class CsrfCallback implements Callback {

    VulTaskImpl vulTask;

    public CsrfCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[CsrfCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同及响应内容一样，则可能存在问题
            if (vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody)) {
                vulTask.message = "formCsrf";
                vulTask.log(call);
            }
        }

    }
}