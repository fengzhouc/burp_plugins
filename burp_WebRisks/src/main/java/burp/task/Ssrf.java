package burp.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.impl.VulResult;
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

    public Ssrf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }

        String evilHost = "evil6666.com";
        //如果有body参数，需要多body参数进行测试
        if (request_body_str.length() > 0){
            //1.先检测是否存在url地址的参数，正则匹配
            String regex = "http[s]?://(.*?)[/&\"]+?"; //分组获取域名
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(request_body_str);
            if (!matcher.find()){//没匹配到则不进行后续验证
                return null;
            }
            String domain = matcher.group(1);
            // 修改为别的域名
            String req_body = request_body_str.replace(domain, evilHost);
            //新的请求包
            okHttpRequester.send(url, method, request_header_list, query, req_body, contentYtpe, new SsrfCallback(this));
        }
        return result;
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
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        // 检查响应中是否存在flag
        if (vulTask.ok_respBody.contains("evil6666.com")) {
            vulTask.message = "SSRF";
            vulTask.log(call);
        }else if (response.isSuccessful()){
            // 可能响应并没有回馈，所以这时响应是成功的也告警
            vulTask.message = "SSRF, Not in Resp";
            vulTask.log(call);
        }
    }
}