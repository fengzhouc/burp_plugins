package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController{

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        //回调对象
        this.callbacks = callbacks;
        //获取扩展helper与stdout对象
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        //插件名称
        callbacks.setExtensionName("IDOR检测");

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


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest)
        {	int row = log.size();
            if ((toolFlag == 4)) {//经过Proxy工具的流量
                //返回信息
                IHttpService iHttpService = messageInfo.getHttpService();
                IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());

                //请求信息
                IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
                String request_info = new String(messageInfo.getRequest());
                //URL url1 = analyzeRequest.getUrl();
                List<IParameter> param_list = analyzeRequest.getParameters();
                List<String> request_header_list = analyzeRequest.getHeaders();

                //返回上面板信息
                String host = iHttpService.getHost();
                String path = analyzeRequest.getUrl().getPath();
                int id = getRowCount() + 1;

                //获取body信息
                String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
                byte[] request_body = messageBody.getBytes();

                //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
                List<String> new_headers1 = new ArrayList<String>();
                for (String header :
                        request_header_list) {
                    if (header.toLowerCase(Locale.ROOT).startsWith("cookie")) {
//                        int index = request_header_list.indexOf(header);
//                        new_headers1.remove(index);
                        continue;
                    }else {
                        new_headers1.add(header);
                    }
                }
                //新的请求包
                byte[] req1 = this.helpers.buildHttpMessage(new_headers1, request_body);
                this.stdout.println(new String(req1));
                //发起请求
                IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req1);
                //新的返回包
                IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
                //如果状态码一样则存在问题
                if (analyzeResponse.getStatusCode() == analyzeResponse1.getStatusCode() && analyzeResponse.equals(analyzeResponse1)) {
                    log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo1),
                            host, path, analyzeRequest.getUrl().getQuery(), helpers.analyzeResponse(messageInfo1.getResponse()).getStatusCode()));
                }

                //2、判断是否有id类的参数的情况
                if (false) {
                    //判断是否有id类的参数
                    //query：[?&]\s*=(\d+)
                    //body(form|json)：[&]?\s*=(\d+)|\"\s\":[\"]?(\d+)
                    //匹配到新建请求重新发送，新响应跟旧响应作比对
                    //1.请求的url中含Jsonp敏感参数
                    Pattern query = Pattern.compile("[?&]\\S*=(\\d+)");
                    Matcher qm = query.matcher(request_header_list.get(0));
                    Pattern body = Pattern.compile("[&]?\\S*=(\\d+)|\"\\S\":[\"]?(\\d+)");
                    Matcher bm = body.matcher(messageBody);
                    //1.url有id类的参数
                    if (qm.find()) {
                        List<String> new_headers2 = request_header_list;
                        String header_first = "";
                        //替换匹配的id为随机id
                        header_first = new_headers2.get(0).replace(qm.group(1), new Random(1000).nextInt() + "");
                        new_headers2.remove(0);
                        new_headers2.add(0, header_first);

                        //新的请求包
                        byte[] req = this.helpers.buildHttpMessage(new_headers2, request_body);

                        //发起请求
                        IHttpRequestResponse messageInfo2 = this.callbacks.makeHttpRequest(iHttpService, req);
                        //新的返回包
                        IResponseInfo analyzeResponse2 = this.helpers.analyzeResponse(messageInfo2.getResponse());
                        //如果状态码一样则存在问题
                        if (analyzeResponse.getStatusCode() == analyzeResponse2.getStatusCode()) {
                            log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo2),
                                    host, path, analyzeRequest.getUrl().getQuery(), helpers.analyzeResponse(messageInfo2.getResponse()).getStatusCode()));
                        }
                    }
                    //2.body有id类的参数
                    else if (bm.find()) {
                        String new_messageBody = messageBody;
                        //替换匹配的id为随机id
                        new_messageBody.replace(qm.group(1), new Random(1000).nextInt() + "");

                        //新的请求包
                        byte[] req = this.helpers.buildHttpMessage(request_header_list, new_messageBody.getBytes());
                        //发起请求
                        IHttpRequestResponse messageInfo3 = this.callbacks.makeHttpRequest(iHttpService, req);
                        //新的返回包
                        IResponseInfo analyzeResponse3 = this.helpers.analyzeResponse(messageInfo3.getResponse());
                        //如果状态码一样则存在问题
                        if (analyzeResponse.getStatusCode() == analyzeResponse3.getStatusCode()) {
                            log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo3),
                                    host, path, param_list.toString(), helpers.analyzeResponse(messageInfo3.getResponse()).getStatusCode()));
                        }
                    }
                }
            }
            fireTableRowsInserted(row, row);
        }
    }

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

    @Override
    public String getTabCaption() {
        return "IDORcHECK";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    /*
    * 下面是Table的一些方法，主要是结果面板的数据展示，可定制，修改如下数据即可
    * */
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
                return "Host";
            case 2:
                return "Path";
            case 3:
                return "Param";
            case 4:
                return "Status";
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
                return logEntry.Host;
            case 2:
                return logEntry.Path;
            case 3:
                return logEntry.Param;
            case 4:
                return logEntry.Status;
            default:
                return "";
        }
    }

    //存在漏洞的url信息类
    //log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
    //                            host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
    private static class LogEntry
    {
        final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        final String Host;
        final String Path;
        final String Param;
        final short Status;


        LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String param, short status)
        {
            this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Param = param;
            this.Path = path;
            this.Host = host;
        }
    }
}
