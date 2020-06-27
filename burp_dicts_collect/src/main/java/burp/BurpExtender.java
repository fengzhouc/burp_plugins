package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab
{

    private JTabbedPane rootPane;
    private JTextField domain_text;
    private JTextArea result_text;
    private JTextArea oper_text;


    private String target_domain = ".*";
    private Pattern domain_regex;

    private Logger logpath;
    private Logger logjs;
    private Logger logparam;
    private Logger logerror;

    private HashSet<String> paths = new HashSet<String>();
    private HashSet<String> params = new HashSet<String>();
    private HashSet<String> jsName = new HashSet<String>();

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        callbacks.setExtensionName("Dict collect");

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        // write a message to our output stream
        stdout.println("Hello output new ");

        addMenuTab();
//        start();

    }


    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        if (toolFlag == 4 && messageIsRequest){
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            parse_request(requestInfo);
        }
    }

    private void parse_request(IRequestInfo requestInfo) {
        //解析url
        String url = requestInfo.getUrl().getPath();
        for (String p:
                url.split("/")) {
            if ("".equals(p)){
                continue;
            }
            if (p.endsWith(".js")){
                jsName.add(p);
                continue;
            }
            if (!p.contains(".")){
                paths.add(p);
                continue;
            }
            // 其他的输出，好检查是否有例外，优化工具
            logerror.info(p);
            output_log(p);
        }

        // 添加参数名，包括了cookie
        List<IParameter> paramList = requestInfo.getParameters();
        for (IParameter param :
                paramList) {
            params.add(param.getName());
            output_log(param.getName());
        }

    }


    private void addMenuTab(){
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //第一层tab，也是顶层窗格
                rootPane = new JTabbedPane();
                //第二层主窗格（tab），用来组合各种组件
                JPanel jPanel_main = new JPanel();
                jPanel_main.setLayout(new BoxLayout(jPanel_main, BoxLayout.Y_AXIS));
                //第二层 - 配置的窗格
                JPanel jPanel_conf = new JPanel();
                jPanel_conf.setLayout(new BoxLayout(jPanel_conf, BoxLayout.X_AXIS));
                JLabel domain = new JLabel("Domain");
                domain_text = new JTextField("please input regex", 70);
                //设置优选大小
                domain_text.setMaximumSize(domain_text.getPreferredSize());

                JButton set = new JButton("Set");
                set.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        //调用设置目标域名的方法
                        String domain_reg = domain_text.getText();
                        setTarget_domain(domain_reg);
                        domain_regex = Pattern.compile(domain_reg);
                        oper_log("set domain regex '" + domain_reg + "' done, gogogo ~ to click start.");

                    }
                });
                JButton start = new JButton("Start");
                JButton stop = new JButton("Stop");
                JLabel split = new JLabel("  |  ");
                //控制开启监听的按钮
                start.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if ("".equals(target_domain) || !target_domain.equals(domain_regex.toString())){
                            oper_log("[error] please first set the domain !!");
                            return;
                        }
                        //调用添加监听的方法
                        start();
                        oper_log("start success. current domain regex was " + target_domain);

                    }
                });
                //控制开启监听的按钮
                stop.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        //调用去除监听的方法
                        stop();
                        oper_log("stop success.");
                        save();
                    }
                });
                jPanel_conf.add(domain);
                jPanel_conf.add(domain_text);
                jPanel_conf.add(set);
                jPanel_conf.add(split);
                jPanel_conf.add(start);
                jPanel_conf.add(stop);

                //第二层 - 输出的窗格
                JTabbedPane jTabbedPane_output = new JTabbedPane();
                jTabbedPane_output.setPreferredSize(jTabbedPane_output.getPreferredSize());
                //输出视图及滚动条
                //结果的
                JScrollPane jScrollPane = new JScrollPane();
                result_text = new JTextArea();
                result_text.setLineWrap(true);
                result_text.setEditable(false);
                jScrollPane.setViewportView(result_text);
                jScrollPane.setVerticalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                //操作的
                JScrollPane jScrollPane1 = new JScrollPane();
                oper_text = new JTextArea();
                oper_text.setLineWrap(true);
                oper_text.setEditable(false);
                jScrollPane1.setViewportView(oper_text);
                jScrollPane1.setVerticalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                //组合
                jTabbedPane_output.addTab("Result log", jScrollPane);
                jTabbedPane_output.addTab("Operatioin log", jScrollPane1);
                //第二层 - 最底部的按钮
                JPanel jPanel_button = new JPanel();
                jPanel_button.setLayout(new BoxLayout(jPanel_button, BoxLayout.X_AXIS));
                JButton jButton = new JButton("submit");
                jPanel_button.add(jButton);
                //第二层主窗格组合各组件
                jPanel_main.add(jPanel_conf);
                jPanel_main.add(jTabbedPane_output);
                jPanel_main.add(jPanel_button);
                //顶层窗格组合各组件
                rootPane.addTab("Options", jPanel_main);

                BurpExtender.this.callbacks.customizeUiComponent(jPanel_main);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);

            }

        });

    }
    private void save(){
        for (String s :
                paths) {
            path_log(s);
        }
        for (String s :
                jsName) {
            js_log(s);
        }
        for (String s :
                params) {
            param_log(s);
        }
        oper_log("save success, file name like " + logerror.getName().split("-")[0] + "-*");
    }

    private void setTarget_domain(String target_domain) {
        this.target_domain = target_domain;
    }

    private void oper_log(String message) {
        oper_text.append(message + "\n");
    }
    private void output_log(String message) {
        result_text.append(message + "\n");
    }

    private void path_log(String message){
        logpath.info(message);
    }
    private void js_log(String message){
        logjs.info(message);
    }
    private void param_log(String message){
        logparam.info(message);
    }

    private void start(){
        String time = String.format("%d", new Date().getTime());
        callbacks.registerHttpListener(this);
        // create new log for start
        logpath = getLog(time + "-path");
        logjs = getLog(time + "-js");
        logparam = getLog(time + "-param");
        logerror = getLog(time + "-error");
    }
    private void stop(){
        callbacks.removeHttpListener(this);
    }

    private Logger getLog(String logname){
        Logger log = Logger.getLogger(logname);
        try {
            FileHandler fileHandler = new FileHandler(logname, true);
            fileHandler.setFormatter(new Formatter() {
                @Override
                public String format(LogRecord record) {
                    return record.getMessage() + "\n";
                }
            });
            log.addHandler(fileHandler);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return log;
    }

    public String getTabCaption() {
        return "Dict collect";
    }

    public Component getUiComponent() {
        return rootPane;
    }


}
