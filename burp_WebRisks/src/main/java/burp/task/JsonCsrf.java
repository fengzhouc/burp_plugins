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
import java.util.List;
import java.util.Locale;

public class JsonCsrf extends VulTaskImpl {
    private static VulTaskImpl instance = null;
    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        if (instance == null){
            instance = new JsonCsrf(helpers, callbacks, log);
        }
        return instance;
    }
    private JsonCsrf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、jsonCsrf：修改content-type为form表单的
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            //csrf会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
            if (check(request_header_list, "Cookie") != null){
                /*
                 * 1、请求头包含application/json
                 */
                if (check(request_header_list, "application/json") != null) {
                    List<String> new_headers1 = new ArrayList<String>();
                    String CT = "Content-Type: application/x-www-form-urlencoded";
                    //新请求修改content-type
                    boolean hasCT = false;
                    for (String header :
                            request_header_list) {
                        // 剔除掉csrf头部
                        if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                            if (header.toLowerCase(Locale.ROOT).contains("content-type")) {
                                header = header.replace("application/json", "application/x-www-form-urlencoded");
                                hasCT = true;
                            }
                            new_headers1.add(header);
                        }
                    }
                    //如果请求头中没有CT，则添加一个
                    if (!hasCT) {
                        new_headers1.add(CT);
                    }
                    request_header_list = new_headers1;
                    if (!method.equalsIgnoreCase("get")) {
                        //新的请求包:content-type
                        okHttpRequester.send(url, method, request_header_list, query, request_body_str, "application/x-www-form-urlencoded", new JsonCsrfCallback(this));
                    }
                }
            }
        }
    }
}

class JsonCsrfCallback implements Callback {

    VulTaskImpl vulTask;

    public JsonCsrfCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[JsonCsrfCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            //如果状态码相同则可能存在问题
            if (vulTask.status == vulTask.ok_code
                    && vulTask.resp_body_str.equalsIgnoreCase(vulTask.ok_respBody)) {
                vulTask.message = "JsonCsrf";
                vulTask.log(call);
            }

        }
    }
}
