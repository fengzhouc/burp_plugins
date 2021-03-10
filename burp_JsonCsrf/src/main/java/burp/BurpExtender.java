package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;


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

        callbacks.setExtensionName("JsonCsrf");

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
            if (toolFlag == 4 || toolFlag == 8 || toolFlag == 16 || toolFlag == 64) {//proxy/spider/scanner/repeater
                //返回信息
                IHttpService iHttpService = messageInfo.getHttpService();
                IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
                String response_info = new String(messageInfo.getResponse());
                String rep_body = response_info.substring(analyzeResponse.getBodyOffset());
                short status_code = analyzeResponse.getStatusCode();
                List<String> response_header_list = analyzeResponse.getHeaders();

                //请求信息
                IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
                String request_info = new String(messageInfo.getRequest());
                List<String> request_header_list = analyzeRequest.getHeaders();

                //返回上面板信息
                String host = iHttpService.getHost();
                String path = analyzeRequest.getUrl().getPath();
                //String param = param_list.toString();
                String param = analyzeRequest.getUrl().getQuery();
                int id = getRowCount() + 1;

                //新请求body
                String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
                byte[] request_body = messageBody.getBytes();
                /*
                 * 1、请求头包含application/json
                 */
                if (check(request_header_list, "application/json") != null) {
                    List<String> new_headers = request_header_list;
                    List<String> new_headers1 = new ArrayList<String>();
                    String header_first = "";
                    String CT = "Content-Type: application/x-www-form-urlencoded";
                    //新请求修改content-type
                    boolean hasOrigin = false;
                    boolean hasCT = false;
                    for (String header :
                            new_headers) {
                        if (header.toLowerCase(Locale.ROOT).contains("content-type")) {
                            header_first = header.replace("application/json", "application/x-www-form-urlencoded");
                            new_headers1.add(header_first);
                            hasCT = true;
                        }else {
                            new_headers1.add(header);
                        }

                    }
                    //如果请求头中没有CT，则添加一个
                    if (!hasCT){
                        new_headers.add(CT);
                    }

                    //新的请求包:content-type
                    byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body);
                    callbacks.printOutput(new String(req));
                    IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
                    //新的返回包
                    IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
                    String response_info1 = new String(messageInfo1.getResponse());
                    String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
                    List<String> response1_header_list = analyzeResponse1.getHeaders();

                    //如果状态码相同则可能存在问题
                    String message = "";
                    if (status_code == analyzeResponse1.getStatusCode()
                            && rep_body.equalsIgnoreCase(rep1_body)){
                        message = "JsonCsrf";
                    }

                    if (!message.equalsIgnoreCase("")){
                        log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo1),
                                host, path, param, status_code, message));
                    }
                    if (analyzeResponse1.getStatusCode() != 200){
                        log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo1),
                                host, path, param, analyzeResponse1.getStatusCode(), ""));
                    }

                }

            }
            fireTableRowsInserted(row, row);
        }
    }

    //检查头部是否包含某信息
    private String check(List<String> headers, String header){
        if (null == headers){
            return null;
        }
        for (String s : headers) {
            if (s.toLowerCase(Locale.ROOT).contains(header)){
                return s;
            }
        }
        return null;
    }


    public String getTabCaption() {
        return "JsonCsrf";
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
        return 6;
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
            case 5:
                return "Risk";
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
            case 5:
                return logEntry.Risk;
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
        final String Host;
        final String Path;
        final String Param;
        final Short Status;
        final String Risk;


        LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String param, Short status, String risk)
        {
            this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Param = param;
            this.Path = path;
            this.Host = host;
            this.Risk = risk;
        }
    }

}
