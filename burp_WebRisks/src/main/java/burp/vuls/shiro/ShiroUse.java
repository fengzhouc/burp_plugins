package burp.vuls.shiro;

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
import java.util.Locale;

public class ShiroUse extends VulTaskImpl {

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new ShiroUse(helpers, callbacks, log);
    }
    private ShiroUse(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    /**
     * 这个只是看下是否使用了shiro，并检测是否使用默认密钥
     */
    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、确认使用shiro
         *  添加cookie：rememberMe=1，检车是否返回cookie：rememberMe=deleteMe
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            List<String> new_headers1 = new ArrayList<>();
            String cookie = "rememberMe=1";
            boolean hasCookie = false;
            //新请求修改origin
            for (String header : request_header_list) {
                if (header.toLowerCase(Locale.ROOT).startsWith("Cookie".toLowerCase(Locale.ROOT))) {
                    new_headers1.add(header + ";" + cookie);
                    hasCookie = true;
                    continue;
                }
                new_headers1.add(header);
            }
            if (!hasCookie){
                new_headers1.add("Cookie: " + cookie);
            }
            String url = iHttpService.getProtocol() + "://" + iHttpService.getHost() + ":" + iHttpService.getPort() + "/";
            okHttpRequester.send(url, "GET", new_headers1, "", "", "", new ShiroUseCallback(this));
            BurpExtender.vulsChecked.add("burp.vuls.shiro.ShiroUse" + host + iHttpService.getPort()); //添加检测标记
        }
    }
}

class ShiroUseCallback implements Callback {

    VulTaskImpl vulTask;

    public ShiroUseCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[ShiroUseCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        // 检查响应体是否有内容
        String setCookie = response.header("Set-Cookie");
        if (setCookie != null && setCookie.contains("=deleteMe")) {
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            vulTask.message = "ShiroUse";
            vulTask.log(call); // TODO 如果使用了则看下是否用了默认key
        }
    }
}