package burp.vuls.other;

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

/**
 * This module tries to identify snoop resources to identify
 * possible information disclosure vulnerabilities and XSS issues
 *
 */
public class SnoopXss extends VulTaskImpl {

    private static final String XSS_PAYLOAD = "<h1>WebRisks";

    private static final List<String> SNOOP_PATHS = Arrays.asList(
            "/snoop.jsp?" + XSS_PAYLOAD,
            "/examples/jsp/snp/snoop.jsp?" + XSS_PAYLOAD,
            "/examples/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/j2ee/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/jsp-examples/snp/snoop.jsp?" + XSS_PAYLOAD
    );

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SnoopXss(helpers, callbacks, log);
    }
    private SnoopXss(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            payloads = loadPayloads("/payloads/SnoopXss.bbm");

            // 构造url
            for (String api :
                    SNOOP_PATHS) {
                String url = String.format("%s://%s:%d%s", iHttpService.getProtocol(), iHttpService.getHost(), iHttpService.getPort(), api);
                okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SnoopXssCallback(this));
            }
            BurpExtender.vulsChecked.add("burp.task.api.SnoopXss" + host + iHttpService.getPort()); //添加检测标记
        }
    }
}

class SnoopXssCallback implements Callback {

    VulTaskImpl vulTask;
    // JSP snoop page</TITLE>
    // <TITLE>JSP snoop page</TITLE>
    // <TITLE>JBossEAP6.0 JSP snoop page</TITLE>
    // Path translated:
    private static final String GREP_STRING = "Path translated";

    public SnoopXssCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SnoopXssCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            if (vulTask.ok_respBody.contains(GREP_STRING) && vulTask.ok_respBody.contains("<h1>WebRisks")) {
                vulTask.message = "SnoopXss";
                vulTask.log(call);
            }
        }
    }
}