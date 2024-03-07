package burp;

import com.alumm0x.listensers.HttpListener;
import com.alumm0x.ui.MainPanel;

import java.awt.*;
import java.security.NoSuchAlgorithmException;


public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static HttpListener httpListener;

    public BurpExtender() throws NoSuchAlgorithmException {
    }


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //回调对象
        BurpExtender.callbacks = callbacks;
        //获取扩展helper与stdout对象
        BurpExtender.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("WebRisks");


        // //定制UI组件
        // callbacks.customizeUiComponent(contentPane);
        // callbacks.customizeUiComponent(panel_a);
        // callbacks.customizeUiComponent(splitPane);
        // callbacks.customizeUiComponent(logTable);
        // callbacks.customizeUiComponent(scrollPane);

        //加载插件输出默认信息
        String author = "alumm0x";
        callbacks.printOutput("#Author: "+author);
        callbacks.printOutput("#Github: https://github.com/fengzhouc/burp_plugins");

        callbacks.registerExtensionStateListener(this);
        //注册监听器
        httpListener = new HttpListener();
        callbacks.registerHttpListener(httpListener);
        //添加标签
        callbacks.addSuiteTab(this);
    }

    public String getTabCaption() {
        return "WebRisks";
    }

    public Component getUiComponent() {
        return MainPanel.getUI();
    }


    @Override
    public void extensionUnloaded() {
    }

}
