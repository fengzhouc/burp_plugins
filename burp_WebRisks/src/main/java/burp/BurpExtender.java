package burp;

import burp.impl.VulResult;
import burp.task.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    private JPanel contentPane;
    private boolean kg = false; //默认关闭
    private JLabel lbConnectStatus; //插件运行状态
    private Table logTable; //视图table对象
    private TableRowSorter<TableModel> sorter; //table排序对象
    private JTextField tfFilterText; //过滤的条件输入框
    private String domain = "/*";

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
                // 整个UI
                contentPane = new JPanel();
                contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
                contentPane.setLayout(new BorderLayout(0, 0));

                // 设置的UI
                JPanel panel = new JPanel();
                FlowLayout flowLayout = (FlowLayout) panel.getLayout();
                flowLayout.setAlignment(FlowLayout.LEFT);
                // 设置：过滤的UI
                JButton btnFilter = new JButton("Domain");
                btnFilter.setToolTipText("filter data: support regex");
                btnFilter.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.domain = tfFilterText.getText();
                    }
                });
                panel.add(btnFilter);
                tfFilterText = new JTextField();
                tfFilterText.setColumns(20);
                tfFilterText.setText("");
                panel.add(tfFilterText);

                JButton btnConn = new JButton("OpenOrClose");
                btnConn.setToolTipText("open or close the pligin to run.");
                btnConn.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.OpenOrClose();
                    }
                });
                panel.add(btnConn);

                JLabel lbConnectInfo = new JLabel("IsRun:");
                panel.add(lbConnectInfo);
                lbConnectStatus = new JLabel("False");
                lbConnectStatus.setForeground(new Color(255, 0, 0));
                panel.add(lbConnectStatus);

                JButton btnClear = new JButton("Clear");
                btnClear.setToolTipText("clear all the result.");
                btnClear.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.ClearResult();
                    }
                });
                panel.add(btnClear);

                JLabel note = new JLabel("注: 如有验证码类的业务,会出现业务功能异常,因为测试是重复发包，所以验证码失效，这类功能需要手测.");
                note.setForeground(new Color(255, 0, 0));
                panel.add(note);
                //添加设置的UI到总UI
                contentPane.add(panel, BorderLayout.NORTH);

                //下面是结果面板的ui
                //分割界面
                JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
                splitPane.setDividerLocation(300);
                contentPane.add(splitPane, BorderLayout.CENTER);

                //上面板，结果面板
                logTable = new Table(BurpExtender.this);
                //TODO 排序后添加数据会报错
                sorter = new TableRowSorter<TableModel>(BurpExtender.this);
//                logTable.setRowSorter(sorter);

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
                callbacks.customizeUiComponent(contentPane);
                callbacks.customizeUiComponent(panel);
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                //添加标签
                callbacks.addSuiteTab(BurpExtender.this);

                //加载插件输出默认信息
                String author = "alumm0x";

                callbacks.printOutput("#Author: "+author);
                callbacks.printOutput("#Task: JsonCsrfAndCors");
                callbacks.printOutput("#Task: IDOR"); // 误报太多, 待改进
                callbacks.printOutput("#Task: Jsonp");
                callbacks.printOutput("#Task: PutJsp[CVE-2017-12615]");
                callbacks.printOutput("#Task: SecureHeader 'X-Frame-Options'");
                callbacks.printOutput("#Task: Redirect");

                //注册监听器
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });


    }
    private void OpenOrClose(){
        // 如果现在close，则open，反之则close
        if(kg){
            lbConnectStatus.setText("False");
            kg = false;
            lbConnectStatus.setForeground(new Color(255,0,0));
        }else{
            lbConnectStatus.setText("True");
            kg = true;
            lbConnectStatus.setForeground(new Color(0,255,0));
        }
    }
    //清空数据
    private void ClearResult(){
        log.clear();
        //通知表格数据变更了
        fireTableDataChanged();
    }
    //过滤数据的功能 TODO 待实现,会报错
    private void Filter(){
        String text = tfFilterText.getText();
        if (text.length() == 0) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter(text));
        }
    }


    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        String host = helpers.analyzeRequest(messageInfo).getUrl().getHost();
//        callbacks.printOutput(host);
        Pattern pattern = Pattern.compile(domain);
        Matcher m = pattern.matcher(host);
        boolean m_host = m.find();
        if (!kg || !m_host){
            return;
        }
        if (!messageIsRequest) {
            int row = log.size();
            VulResult result = null;
            if (toolFlag == 4 || toolFlag == 8 || toolFlag == 16 || toolFlag == 64) {//proxy4/spider8/scanner16/repeater64
                // jsoncsrf的检测及CORS
                new JsonCsrfAndCors(helpers, callbacks, log, messageInfo).run();
                // 未授权访问, 误报太多, 待改进
                new IDOR(helpers, callbacks, log, messageInfo).run();
                // jsonp
                new Jsonp(helpers, callbacks, log, messageInfo).run();
                // tomcat put jsp
                new PutJsp(helpers, callbacks, log, messageInfo).run();
                // secure headers
                new SecureHeader(helpers, callbacks, log, messageInfo).run();
                // Redirect
                new Redirect(helpers, callbacks, log, messageInfo).run();

            }
            int lastRow = getRowCount();
            /*
            * 1、无结果, row == lastRow
            * 2、1个或以上结果,row < lastRow
            * 所以，有添加的时候在通过有添加数据
            * */
            if (row < lastRow) {
                /*
                 * fix：java.lang.IndexOutOfBoundsException: Invalid range
                 * 没有添加数据还通知有数据被添加，会导致setAutoCreateRowSorter排序出现Invalid range异常
                 */
                //通知所有的listener在这个表格中第firstrow行至lastrow列已经被加入了
                fireTableRowsInserted(row, lastRow - 1);
            }
        }
    }


    public String getTabCaption() {
        return "WebRisks";
    }

    public Component getUiComponent() {
        return contentPane;
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
            LogEntry logEntry = log.get(logTable.convertRowIndexToModel(row));
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
        // 解决setAutoCreateRowSorter排序后,获取row乱了,导致获取表中数据时出现异常
        LogEntry logEntry = log.get(logTable.convertRowIndexToModel(rowIndex));
        if (logEntry != null) {

            switch (columnIndex) {
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
        }else {
            return "";
        }
    }

//    @Override
//    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
//        super.setValueAt(aValue, logTable.convertRowIndexToModel(rowIndex), columnIndex);
//    }

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
