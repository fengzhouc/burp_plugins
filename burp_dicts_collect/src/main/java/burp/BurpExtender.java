package burp;

import com.sun.tools.javac.util.StringUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //回调对象
        this.callbacks = callbacks;
        //获取扩展helper与stdout对象
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName("DictCollect");

        //创建UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                //分割界面
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割

                //上面板，结果面板
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable); //滚动条
                splitPane.setLeftComponent(scrollPane);

                //下面板，请求响应的面板
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                //定制UI组件
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                //添加标签
                callbacks.addSuiteTab(BurpExtender.this);

                //加载插件输出默认信息
                String author = "alumm0x";

                callbacks.printOutput("#Author:"+author);

                //注册监听器
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });


    }


    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            int row = log.size();
            if (toolFlag == 4 || toolFlag == 8 || toolFlag == 16) {//proxy/spider/scanner
                int id = getRowCount() + 1;

                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                URL url = requestInfo.getUrl();
                String host = url.getHost();
                //子域名的数据数组，eg：a.b.c.d.com，a/b/c/a.b.c
                String[] domains;
                if (!isIP(host)){
                    String[] ha = host.split("\\.");
                    //剔除二级域名后的每个节点数据
                    String[] han = Arrays.copyOfRange(ha,0, ha.length-2);
                    List<String> arrDm = new ArrayList<String>(Arrays.asList(han));
                    //添加完整子域名串,但是在有多个节点数据的时候
                    if (han.length > 1) {
                        String ats = arrayToStr(han, ".");
                        arrDm.add(ats.substring(0, ats.length() - 1));
                    }
                    //子域名的数据数组，eg：a.b.c.d.com，a/b/c/a.b.c
                    domains = arrDm.toArray(new String[0]);
                }else {
                    domains = new String[]{};
                }

                String path = url.getPath();
                //目录的数据数组
                String[] dirs = path.split("/");
                //文件的数据数组
                String[] files = null;
                List<String> up = Arrays.asList(dirs);
                //up是数组转换的，不能add/remove，所以需要重新new一个ArrayList
                List<String> arrList = new ArrayList<String>(up);
                if (arrList.size() > 0 && arrList.get(arrList.size()-1).contains(".")){
                    //是资源文件,生成文件数据数组
                    String file = arrList.get(arrList.size()-1).trim();
//                    stdout.println(file);
                    //文件名数据的类型白名单
                    if (!file.endsWith(".css")
                            && !file.endsWith(".png")
                            && !file.endsWith(".gif")
                            && !file.endsWith(".jpg")
                            && !file.endsWith(".ico")
                            && !file.endsWith(".woff2")
                            && !file.endsWith(".svg")
                            && !file.endsWith(".ttf")){
                        //将完整的文件路径也加进去，path
                        files = new String[]{file, path};
                    }
                    //移除dirs中的文件
                    arrList.remove(file);
                    //将完整的路径也添加进去(去掉最后的一个文件名)，path
                    arrList.add(path.substring(0, path.lastIndexOf("/")));
                }else {
                    //纯api的路径，不需要处理文件的
                    //将完整的路径也添加进去，path
                    arrList.add(path);
                }
//                stdout.println(path + "##" + arrList.size());
                dirs = arrList.toArray(new String[0]);

                List<IParameter> params = requestInfo.getParameters();
                List<String> pas = new ArrayList<String>();
                for (IParameter p :
                        params) {
                    pas.add(p.getName());
                }
                //参数名的数据数组
                String[] ps = pas.toArray(new String[0]);
                //将结果写入文件
                write(domains, dirs, ps, files);
                //设置面板数据
                log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
                        arrayToStr(domains, ","), arrayToStr(dirs, ","),
                        arrayToStr(ps, ","), arrayToStr(files, ",")));

            }
            fireTableRowsInserted(row, row);
        }
    }

    private boolean isIP(String addr) {

        if ("".equals(addr) || addr.length() < 7 || addr.length() > 15) {
            return false;
        }
        /*
         * 判断IP格式和范围
         */
        String rexp = "^([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}$";
        Pattern pat = Pattern.compile(rexp);
        Matcher mat = pat.matcher(addr);
        boolean ipAddress = mat.find();
        return ipAddress;

    }

    private void write(String[] domains, String[] paths,String[] params, String[] files){
        String f = "files.txt";
        String d = "domains.txt";
        String pa = "params.txt";
        String ps = "paths.txt";
        // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
        if (domains.length != 0){
            FileWriter writer = null;
            try {
                writer = new FileWriter(d, true);
                for (String s :
                        domains) {
                    if ("".equals(s)){
                        continue;
                    }
                    writer.write(s+"\r");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                try {
                    writer.close();
                } catch (IOException e) {}
            }
        }
        if (paths.length != 0){
            FileWriter writer = null;
            try {
                writer = new FileWriter(ps, true);
                for (String s :
                        paths) {
                    if ("".equals(s)){
                        continue;
                    }
                    writer.write(s+"\r");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                try {
                    writer.close();
                } catch (IOException e) {}
            }
        }
        if (params.length != 0){
            FileWriter writer = null;
            try {
                writer = new FileWriter(pa, true);
                for (String s :
                        params) {
                    if ("".equals(s)){
                        continue;
                    }
                    writer.write(s+"\r");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                try {
                    writer.close();
                } catch (IOException e) {}
            }
        }
        if (null != files && files.length != 0){
            //TODO 分类文件类型
            //js/jsp/php/action/do/asp/aspx
            FileWriter writer = null;
            try {
                writer = new FileWriter(f, true);
                for (String s :
                        files) {
                    if ("".equals(s)){
                        continue;
                    }
                    writer.write(s+"\r");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                try {
                    writer.close();
                } catch (IOException e) {}
            }
        }

    }

    private String arrayToStr(String[] arr, String splitSTR){
        if (null == arr){
            return "";
        }
        StringBuffer stringBuffer = new StringBuffer();
        for (String s : arr) {
            stringBuffer.append(s);
            stringBuffer.append(splitSTR);
        }
        return stringBuffer.toString();
    }



    public String getTabCaption() {
        return "DictCollector";
    }

    public Component getUiComponent() {
        return splitPane;
    }

    /*
     * 下面是Table的一些方法，主要是结果面板的数据展示，可定制，修改如下数据即可
     * */
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }
    //上面板结果的数量，log是存储检测结果的
    @Override
    public int getRowCount()
    {
        return log.size();
    }
    //结果面板的字段数量
    @Override
    public int getColumnCount()
    {
        return 5;
    }
    //结果面板字段的值
    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Id";
            case 1:
                return "Host(domains.txt)";
            case 2:
                return "Paths(dirs.txt)";
            case 3:
                return "Params(params.txt)";
            case 4:
                return "Files(files.txt)";
            default:
                return "";
        }
    }
    //获取数据到面板展示
    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.Hosts;
            case 2:
                return logEntry.Paths;
            case 3:
                return logEntry.Params;
            case 4:
                return logEntry.Files;
            default:
                return "";
        }
    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }

    //存在漏洞的url信息类
    //log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
    //                            host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
    private static class LogEntry
    {
        final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        final String Hosts;
        final String Paths;
        final String Params;
        final String Files;


        LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String param, String files)
        {
            this.Files = files;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Params = param;
            this.Paths = path;
            this.Hosts = host;
        }
    }

}
