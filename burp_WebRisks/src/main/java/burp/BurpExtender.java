package burp;

import burp.task.IDOR;
import burp.task.JsonCsrfAndCors;
import burp.task.Jsonp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;


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

        callbacks.setExtensionName("WebRisks");

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
            String message = "";
            if (toolFlag == 4 || toolFlag == 8 || toolFlag == 16) {//proxy4/spider8/scanner16/repeater64
                // jsoncsrf的检测及CORS
                new JsonCsrfAndCors(helpers, callbacks, log, messageInfo, getRowCount()).run();
                // 未授权访问
                new IDOR(helpers, callbacks, log, messageInfo, getRowCount()).run();
                // jsonp
                new Jsonp(helpers, callbacks, log, messageInfo, getRowCount()).run();

            }
            fireTableRowsInserted(row, row);
        }
    }


    public String getTabCaption() {
        return "WebRisks";
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
                return "Method";
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
                return logEntry.Method;
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
    public static class LogEntry
    {
        public final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        public final String Host;
        public final String Path;
        public final String Method;
        public final Short Status;
        public final String Risk;


        public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String method, Short status, String risk)
        {
            this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Method = method;
            this.Path = path;
            this.Host = host;
            this.Risk = risk;
        }
    }

}
