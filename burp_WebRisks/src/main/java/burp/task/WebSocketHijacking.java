package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.impl.VulResult;
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

public class WebSocketHijacking extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new WebSocketHijacking(helpers, callbacks, log);
    }
    private WebSocketHijacking(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * websocket的csrf，类似jsonp，是不受cors限制的
         *   1.使用cookie
         *   2.修改/添加请求头Origin为http://evil.com，看是否能连接成功
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            //利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (check(request_header_list, "Cookie") != null){
                /*
                 * websocket请求跨域连接
                 * 修改origin
                 */
                if (check(request_header_list, "Sec-WebSocket-Key") != null){
                    List<String> new_headers = new ArrayList<>();
                    String evilOrigin = "http://evil.com";
                    //新请求修改origin
                    for (String header :
                            request_header_list) {
                        // 剔除掉csrf头部
                        if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                            if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                                new_headers.add(header);
                            }
                        }
                    }
                    new_headers.add("Origin: " + evilOrigin);
                    okHttpRequester.send(url, method, new_headers, query, request_body_str, contentYtpe, new WebSocketHijackingCallback(this));
                }
            }
        }
    }
}

class WebSocketHijackingCallback implements Callback {

    VulTaskImpl vulTask;

    public WebSocketHijackingCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[WebSocketHijackingCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response);
        if (vulTask.ok_code == 101){
            vulTask.message = "WebSocketHijacking";
            vulTask.log(call);
        }
    }
}