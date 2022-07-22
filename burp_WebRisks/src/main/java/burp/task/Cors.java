package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.HeaderTools;
import burp.util.HttpRequestResponseFactory;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class Cors extends VulTaskImpl {

    private static VulTaskImpl instance = null;
    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        if (instance == null){
            instance = new Cors(helpers, callbacks, log);
        }
        return instance;
    }
    private Cors(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、cors
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (check(request_header_list, "Cookie") != null){
                /*
                 * ajax请求跨域获取数据的条件
                 * 1、Access-Control-Allow-Credentials为true
                 * 2、Access-Control-Allow-Origin为*或者根据origin动态设置
                 */
                if (check(response_header_list, "Access-Control-Allow-Origin") != null){
                    String origin = check(response_header_list, "Access-Control-Allow-Origin");
                    String credentials = check(response_header_list, "Access-Control-Allow-Credentials");
                    if (credentials != null && credentials.contains("true")){
                        if (origin.contains("*")) {
                            message += "CORS Any";
                            messageInfo_r = messageInfo;
                        }else {
                            List<String> new_headers1 = new ArrayList<String>();
                            String evilOrigin = "http://evil.com";
                            //新请求修改origin
                            for (String header :
                                    request_header_list) {
                                // 剔除掉csrf头部
                                if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                                    if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                                        new_headers1.add(header);
                                    }
                                }
                            }
                            new_headers1.add("Origin: "+evilOrigin);
                            request_header_list = new_headers1;
                            okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new CorsCallback(this));
                        }
                    }
                }
            }
        }
    }
}

class CorsCallback implements Callback {

    VulTaskImpl vulTask;

    public CorsCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[CorsCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        List<String> hds = Arrays.asList(response.headers().toString().split("\n"));
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        if (vulTask.check(hds, "Access-Control-Allow-Origin").contains("http://evil.com")){
            vulTask.message = "CORS Dynamic and Without csrfToken";
            vulTask.log(call);
        }else {
            if (!"".equalsIgnoreCase(vulTask.message)){
                vulTask.log(call);
            }
        }
    }
}