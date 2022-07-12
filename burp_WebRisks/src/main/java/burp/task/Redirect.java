package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.HttpRequestResponseFactory;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Redirect extends VulTaskImpl {

    public Redirect(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、有字段则添加字段在测试
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }

        //1.请求的url中含redirect敏感参数
        if (query.contains("redirect=")
                || query.contains("redirect_url=")
                || query.contains("redirect_uri=")
                || query.contains("callback=")
                || query.contains("url=")
                || query.contains("goto="))
        {
            String new_query = "redirect=http://evil.com/test&" +
                    "redirect_url=http://evil.com/test&" +
                    "redirect_uri=http://evil.com/test&" +
                    "callback=http://evil.com/test&" +
                    "url=http://evil.com/test&" +
                    "goto=http://evil.com/test&" +
                    query;

            //新的请求包
            okHttpRequester.send(url, method, request_header_list, new_query, request_body_str, contentYtpe, new RedirectCallback(this));
        }

        return result;
    }
}

class RedirectCallback implements Callback {

    VulTaskImpl vulTask;

    public RedirectCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[RedirectCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
        //检查响应头Location
        if (response.isRedirect()){
            String location = vulTask.ok_respHeaders.get("Location");
            if (location != null &&location.contains("evil.com")) {
                vulTask.message = "Redirect";
            }
        }else if (vulTask.ok_respBody.contains("evil.com")) { //检查响应体中，有些是页面加载后重定向
            vulTask.message = "Redirect or DomXss";
        }
        if (!vulTask.message.equalsIgnoreCase("")){
            vulTask.log(call);
        }
    }
}