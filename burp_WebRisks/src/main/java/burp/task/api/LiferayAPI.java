package burp.task.api;

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
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LiferayAPI extends VulTaskImpl {
    private final static List<String> PATHS = Arrays.asList(
            "/api/jsonws",  //JSON，https://help.liferay.com/hc/en-us/articles/360018151631-JSON-Web-Services，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
            "/api/axis",    //SOAP，https://help.liferay.com/hc/en-us/articles/360017872492-SOAP-Web-Services，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
            "/api/liferay", //Liferay tunnel servlet，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
            "/webdav"       //WebDAV servlet，https://help.liferay.com/hc/en-us/articles/360018172711-Desktop-Access-to-Documents-and-Media，https://help.liferay.com/hc/en-us/articles/360017872472-Service-Security-Layers
    );

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new LiferayAPI(helpers, callbacks, log);
    }
    private LiferayAPI(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            payloads = loadPayloads("/payloads/LiferayAPI.bbm");

            // 构造url
            for (String api :
                    PATHS) {
                String url = String.format("%s://%s:%d%s", iHttpService.getProtocol(), iHttpService.getHost(), iHttpService.getPort(), api);
                okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new LiferayAPICallback(this));
            }
            BurpExtender.vulsChecked.add("burp.task.api.LiferayAPI" + host + iHttpService.getPort()); //添加检测标记
        }
    }
}

class LiferayAPICallback implements Callback {

    VulTaskImpl vulTask;
    private final static List<Pattern> PATTERNS = Arrays.asList(
            Pattern.compile(".*<title>json-web-services-api<\\/title>.*", Pattern.DOTALL),
            Pattern.compile(".*<h2>And now\\.\\.\\. Some Services<\\/h2>.*", Pattern.DOTALL),
            Pattern.compile(".*Internal Server Error.*An error occurred while accessing the requested resource\\..*", Pattern.DOTALL)
    );

    public LiferayAPICallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[LiferayAPICallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            for (Pattern p :
                    PATTERNS) {
                Matcher m = p.matcher(vulTask.ok_respBody);
                if (m.find()){
                    vulTask.message = "LiferayAPI";
                    vulTask.log(call);
                    break;
                }
            }
        }
    }
}