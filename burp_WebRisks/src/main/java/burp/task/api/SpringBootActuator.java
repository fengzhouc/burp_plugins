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

/***
 *
 * Spring Boot Actuator
 *
 *
 *
 *
 * References:
 *  - http://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#production-ready-endpoints
 *
 *
 */
public class SpringBootActuator extends VulTaskImpl {
    private static final List<String> SPRINGBOOT_ACTUATOR_PATHS = Arrays.asList(
            "/health",
            "/manager/health",
            "/actuator",
            "/actuator/jolokia/list",
            "/jolokia/list",
            "/env"
    );

    public static VulTaskImpl getInstance(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log){
        return new SpringBootActuator(helpers, callbacks, log);
    }
    private SpringBootActuator(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log) {
        super(helpers, callbacks, log);
    }

    @Override
    public void run() {
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(path, add)){
            payloads = loadPayloads("/payloads/SpringBootActuator.bbm");

            // 构造url
            for (String api :
                    SPRINGBOOT_ACTUATOR_PATHS) {
                String url = String.format("%s://%s:%d%s", iHttpService.getProtocol(), iHttpService.getHost(), iHttpService.getPort(), api);
                okHttpRequester.send(url, method, request_header_list, query, request_body_str, contentYtpe, new SpringBootActuatorCallback(this));
            }
            BurpExtender.vulsChecked.add("burp.task.api.SpringBootActuator" + host + iHttpService.getPort()); //添加检测标记
        }
    }
}

class SpringBootActuatorCallback implements Callback {

    VulTaskImpl vulTask;
    private static final List<String> GREP_STRINGS = Arrays.asList(
            "{\"status\":\"UP\"}",
            "{\"_links\":",
            "org.spring",
            "java.vendor"
    );

    public SpringBootActuatorCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        vulTask.callbacks.printError("[SpringBootActuatorCallback-onFailure] " + e.getMessage() + "\n" + new String(vulTask.ok_respInfo));
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        if (response.isSuccessful()){
            vulTask.setOkhttpMessage(call, response); //保存okhttp的请求响应信息
            for (String b:
                 GREP_STRINGS) {
                if (vulTask.ok_respBody.contains(b)) {
                    vulTask.message = "SpringBootActuator";
                    vulTask.log(call);
                }
            }
        }
    }
}