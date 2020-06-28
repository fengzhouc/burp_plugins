package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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
    private JTextArea path_text;
    private JTextArea js_text;
    private JTextArea param_text;
    private JTextArea other_text;
    private JTextArea oper_text;


    private String target_domain = ".*";
    private Pattern domain_regex = Pattern.compile(target_domain);

    private String savefile = String.format("%d", new Date().getTime());

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

        // toolFlag https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks
        if (toolFlag == 4 || toolFlag == 8 || toolFlag == 16){//proxy/spider/scanner
            if (messageIsRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                parse_request(requestInfo);
            }
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
                js_log(p);
                continue;
            }
            if (!p.contains(".")){
                paths.add(p);
                path_log(p);
                continue;
            }
            other_log(p);

        }

        // 添加参数名，包括了cookie
        List<IParameter> paramList = requestInfo.getParameters();
        for (IParameter param :
                paramList) {
            params.add(param.getName());
            param_log(param.getName());
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
                        savefile = String.format("%d", new Date().getTime());
                        //调用设置目标域名的方法
                        String domain_reg = domain_text.getText();
                        setTarget_domain(domain_reg);
                        domain_regex = Pattern.compile(domain_reg);
                        oper_log("set domain regex '" + domain_reg + "' done, gogogo ~ to click start.");

                    }
                });
                JButton start = new JButton("Start");
                JButton stop = new JButton("Stop");
                JButton save = new JButton("Save");
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
                save.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        save();
                    }
                });
                jPanel_conf.add(domain);
                jPanel_conf.add(domain_text);
                jPanel_conf.add(set);
                jPanel_conf.add(save);
                jPanel_conf.add(split);
                jPanel_conf.add(start);
                jPanel_conf.add(stop);

                //第二层 - 输出的窗格
                JTabbedPane jTabbedPane_output = new JTabbedPane();
                jTabbedPane_output.setPreferredSize(jTabbedPane_output.getPreferredSize());
                //输出视图及滚动条
                //结果的
                JTabbedPane output = new JTabbedPane();
                output.setPreferredSize(output.getPreferredSize());
                JScrollPane path_log = new JScrollPane();
                path_text = new JTextArea();
                path_text.setLineWrap(true);
                path_text.setEditable(false);
                path_log.setViewportView(path_text);
                path_log.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                JScrollPane js_log = new JScrollPane();
                js_text = new JTextArea();
                js_text.setLineWrap(true);
                js_text.setEditable(false);
                js_log.setViewportView(js_text);
                js_log.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                JScrollPane param_log = new JScrollPane();
                param_text = new JTextArea();
                param_text.setLineWrap(true);
                param_text.setEditable(false);
                param_log.setViewportView(param_text);
                param_log.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                JScrollPane other_log = new JScrollPane();
                other_text = new JTextArea();
                other_text.setLineWrap(true);
                other_text.setEditable(false);
                other_log.setViewportView(param_text);
                other_log.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                output.addTab("path log", path_log);
                output.addTab("param log", param_log);
                output.addTab("js log", js_log);
                output.addTab("other log", other_log);
                //操作的
                JScrollPane jScrollPane1 = new JScrollPane();
                oper_text = new JTextArea();
                oper_text.setLineWrap(true);
                oper_text.setEditable(false);
                jScrollPane1.setViewportView(oper_text);
                jScrollPane1.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                //组合
                jTabbedPane_output.addTab("Result", output);
                jTabbedPane_output.addTab("Operatioin log", jScrollPane1);
                //第二层 - 最底部的按钮
                JLabel author = new JLabel("Author@alumm0x");

                //第二层主窗格组合各组件
                jPanel_main.add(jPanel_conf);
                jPanel_main.add(jTabbedPane_output);
                jPanel_main.add(author);
                //顶层窗格组合各组件
                rootPane.addTab("Options", jPanel_main);

                BurpExtender.this.callbacks.customizeUiComponent(jPanel_main);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);

            }

        });

    }
    private void save(){
        try {
            FileOutputStream path = new FileOutputStream(savefile + "-path.txt");
            FileOutputStream js = new FileOutputStream(savefile + "-js.txt");
            FileOutputStream param = new FileOutputStream(savefile + "-param.txt");
            for (String s :
                    paths) {
                path.write(s.getBytes());
                path.write("\n".getBytes());
            }
            for (String s :
                    jsName) {
                js.write(s.getBytes());
                js.write("\n".getBytes());
            }
            for (String s :
                    params) {
                param.write(s.getBytes());
                param.write("\n".getBytes());
            }
            oper_log("save success, file name like '" + savefile + "-*.txt'.");
            paths.clear();
            params.clear();
            jsName.clear();

        } catch (FileNotFoundException e) {
            oper_log("[error] " + e.getMessage());
        } catch (IOException e) {
            oper_log("[error] " + e.getMessage());
        }

    }

    private void setTarget_domain(String target_domain) {
        this.target_domain = target_domain;
    }

    private void oper_log(String message) {
        oper_text.append(message + "\n");
    }

    private void path_log(String message){
        path_text.append(message + "\n");
    }
    private void js_log(String message){
        js_text.append(message + "\n");
    }
    private void param_log(String message){
        param_text.append(message + "\n");
    }
    private void other_log(String message){
        other_text.append(message + "\n");
    }

    private void start(){
        callbacks.registerHttpListener(this);
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
