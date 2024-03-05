package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ssrf extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new Ssrf(helpers, callbacks, log);
    }
    private Ssrf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            payloads = loadPayloads("/payloads/SsrfRegex.bbm");
            String regex = "http[s]?://(.*?)[/&\"]+?\\w*?"; //分组获取域名
            String evilHost = "evil6666.com";
            //如果有body参数，需要多body参数进行测试
            if (request_body_str.length() > 0){
                //1.先检测是否存在url地址的参数，正则匹配
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(request_body_str);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String domain = matcher.group(1);
                    payloads += "\n" + domain;
                    // 修改为别的域名
                    String req_body = request_body_str.replace(domain, evilHost);
                    //新的请求包
                    okHttpRequester.send(url, method, request_header_list, query, req_body, contentYtpe, new SsrfCallback(this));
                }
            }else if (query != null){
                //1.先检测是否存在url地址的参数，正则匹配
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(query);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String domain = matcher.group(1);
                    payloads += "\n" + domain;
                    callbacks.printOutput(domain);
                    // 修改为别的域名
                    String req_query = query.replace(domain, evilHost);
                    //新的请求包
                    okHttpRequester.send(url, method, request_header_list, req_query, request_body_str, contentYtpe, new SsrfCallback(this));
                }
            }
        }
    }

}

class SsrfCallback implements Callback {

    VulTaskImpl vulTask;

    public SsrfCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SsrfCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        // 检查响应中是否存在flag
        if (vulTask.ok_respBody.contains("evil6666.com")) {
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            vulTask.message = "SSRF";
            vulTask.log(call);
        }else if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            // 可能响应并没有回馈，所以这时响应是成功的也告警
            vulTask.message = "SSRF, Not in Resp";
            vulTask.log(call);
        }
    }
}