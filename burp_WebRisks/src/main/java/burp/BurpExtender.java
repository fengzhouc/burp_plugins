package burp;

import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.task.*;
import burp.util.LRUCache;
import burp.util.Requester;
import burp.vuls.LandrayOa;
import burp.vuls.PutJsp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IMessageEditor desViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    private JPanel contentPane;
    private boolean kg = false; //默认关闭
    private JLabel lbConnectStatus; //插件运行状态
    private Table logTable; //视图table对象
    private TableRowSorter<TableModel> sorter; //table排序对象
    private JTextField tfFilterText; //过滤的条件输入框
    private JTextField tfFilterText_c; //Cookie
    private JTextField tfFilterText_cve; //cve 漏洞扫描
    private String domain = ".*";
    public static String cookie = "cookie:xxx";
    private String url = "";
    private String vulsChecked = "none"; //是否已经检测cve漏洞
    private final BlockingQueue<VulTaskImpl> queue = new LinkedBlockingDeque<>(); //任务队列
    JSplitPane splitPane;

    //本地缓存，存放已检测过的请求，检测过就不检测了
    private final LRUCache localCache = new LRUCache(10000);
    private final MessageDigest md = MessageDigest.getInstance("MD5");

    public BurpExtender() throws NoSuchAlgorithmException {
    }


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
                btnFilter.setPreferredSize(new Dimension(70,28)); // 按钮大小
                btnFilter.setToolTipText("配置扫描的域名,支持正则,填写后需点击此按钮");
                btnFilter.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        String d = tfFilterText.getText();
                        if ("".equalsIgnoreCase(d) || null != d) {
                            BurpExtender.this.domain = d;
                        }
                    }
                });
                panel.add(btnFilter);
                tfFilterText = new JTextField();
                tfFilterText.setColumns(20);
                tfFilterText.setText("*");
                panel.add(tfFilterText);

                JButton btnConn = new JButton("On-Off");
                btnConn.setPreferredSize(new Dimension(70,28)); // 按钮大小
                btnConn.setToolTipText("基础Web漏洞扫描器开关");
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
                btnClear.setPreferredSize(new Dimension(70,28)); // 按钮大小
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

                // cookie设置
                JPanel panel_c = new JPanel();
                FlowLayout flowLayout_c = (FlowLayout) panel_c.getLayout();
                flowLayout_c.setAlignment(FlowLayout.LEFT);
                // 设置cookie的UI
                JButton btnFilter_c = new JButton("Cookie");
                btnFilter_c.setToolTipText("填写后需点击此按钮,才能设置Cookie,格式 cookie:xxx,token也可以");
                btnFilter_c.setPreferredSize(new Dimension(70,28)); // 按钮大小
                btnFilter_c.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        String d = tfFilterText_c.getText();
                        if ("".equalsIgnoreCase(d) || null != d) {
                            BurpExtender.this.cookie = d;
                        }
                    }
                });
                panel_c.add(btnFilter_c);
                tfFilterText_c = new JTextField();
                tfFilterText_c.setColumns(45);
                tfFilterText_c.setText("");
                panel_c.add(tfFilterText_c);
                JLabel note_c = new JLabel("注: 测试需要他人的会话凭证, eg:'Cookie: xxxxxx' 或是 'x-auth-token: xxx'.");
                note_c.setForeground(new Color(255, 0, 0));
                panel_c.add(note_c);
                // TODO 带规划的cve扫描区
                // CVE扫描设置
                JPanel panel_cve = new JPanel();
                FlowLayout flowLayout_cve = (FlowLayout) panel_cve.getLayout();
                flowLayout_cve.setAlignment(FlowLayout.LEFT);
                // 设置cve的UI
                JButton btnFilter_cve = new JButton("Url");
                btnFilter_cve.setPreferredSize(new Dimension(70,28)); // 按钮大小
                btnFilter_cve.setToolTipText("CVE漏洞扫描的目标url,填写后需点击此按钮");
                btnFilter_cve.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        String d = tfFilterText_cve.getText();
                        if ("".equalsIgnoreCase(d) || null != d) {
                            BurpExtender.this.url = d;
                        }
                    }
                });
                panel_cve.add(btnFilter_cve);
                tfFilterText_cve = new JTextField();
                tfFilterText_cve.setColumns(45);
                tfFilterText_cve.setText("");
                panel_cve.add(tfFilterText_cve);
                JButton button_cve = new JButton("Scan");
                button_cve.setToolTipText("不设置url,则扫描下方选中的网站");
                button_cve.setPreferredSize(new Dimension(70,28)); // 按钮大小
                button_cve.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        // TODO 待规划,看如何设计更以拓展，因为会很多payload
                        // url空，即直接点击Scan，则扫描选中的域名
                    }
                });
                panel_cve.add(button_cve);
                JLabel note_cve = new JLabel("注: cve漏洞扫描, 待规划");
                note_cve.setForeground(new Color(255, 0, 0));
                panel_cve.add(note_cve);
                // cve UI end
                //构造总设置UI
                JPanel panel_a = new JPanel();
                BoxLayout boxLayout = new BoxLayout(panel_a, BoxLayout.Y_AXIS);
                panel_a.setLayout(boxLayout);
                panel_a.add(panel);
                panel_a.add(panel_c);
//                panel_a.add(panel_cve); // cve待规划
                //添加设置的UI到总UI
                contentPane.add(panel_a, BorderLayout.NORTH);

                //下面是结果面板的ui
                //分割界面
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
                contentPane.add(splitPane, BorderLayout.CENTER);

                //上面板，结果面板
                logTable = new Table(BurpExtender.this);
                //TODO 排序后添加数据会报错
                sorter = new TableRowSorter<TableModel>(BurpExtender.this);
//                logTable.setRowSorter(sorter);

                JScrollPane scrollPane = new JScrollPane(logTable); //滚动条
                splitPane.setLeftComponent(scrollPane);

                //初始化下面板的Message对象
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                desViewer = callbacks.createMessageEditor(BurpExtender.this, false);

                //定制UI组件
                callbacks.customizeUiComponent(contentPane);
                callbacks.customizeUiComponent(panel_a);
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);

                //添加标签
                callbacks.addSuiteTab(BurpExtender.this);

                //加载插件输出默认信息
                String author = "alumm0x";

                callbacks.printOutput("#Author: "+author);
                callbacks.printOutput("    ");
                callbacks.printOutput("##Web Basic");
                callbacks.printOutput("#Task: JsonCsrf");
                callbacks.printOutput("#Task: Cors");
                callbacks.printOutput("#Task: IDOR");
                callbacks.printOutput("#Task: IDOR_xy"); // 横纵向越权
                callbacks.printOutput("#Task: Jsonp");
                callbacks.printOutput("#Task: SecureCookie");
                callbacks.printOutput("#Task: Https");
                callbacks.printOutput("#Task: SecureHeader 'X-Frame-Options'");
                callbacks.printOutput("#Task: Redirect");
                callbacks.printOutput("#Task: IndexOf");
                callbacks.printOutput("#Task: SqlInject");
                callbacks.printOutput("#Task: XssEeflect");
                callbacks.printOutput("    ");
                callbacks.printOutput("##CVE");
//                callbacks.printOutput("#Task: PutJsp[CVE-2017-12615]");
                callbacks.printOutput("#Task: LandrayOa");

                //注册监听器
//                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
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
        vulsChecked = "none"; //清空标记
        localCache.clear(); //清空时清空缓存
        callbacks.printOutput("clear cache success.");
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

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse messageInfo) {
        URL urlo = this.helpers.analyzeRequest(messageInfo).getUrl();
        String url = urlo.toString();
        byte[] requestInfo = messageInfo.getRequest();
        //计算MD5
        md.update(requestInfo);
        String md5 = new BigInteger(1, md.digest()).toString(16);

        //检查插件是否开启
        String host = helpers.analyzeRequest(messageInfo).getUrl().getHost();
        // callbacks.printOutput(host);
        Pattern pattern = Pattern.compile(domain);
        Matcher m = pattern.matcher(host);
        boolean m_host = m.find();
        if (!kg || !m_host){ //是否开启插件，开启后匹配设置的domain才会尽心扫描
            return null;
        }

        // 解决：建一个list存放任务，下面for循环执行任务
        List<VulTaskImpl> tasks = new ArrayList<>();
        // TODO bean注入及参数分析任务是必须要重复运行的
        // #####总是执行的任务创建Start
        // #####总是执行的任务创建End

        // 检查是否在缓存中
        if (localCache.get(md5) != null){ //如果在缓存中则返回
            callbacks.printOutput("inCache " + url);
            return null;
        }
        //正式进入测试
//        int row = log.size();
        VulResult result = null;
        // TODO 下面这里不行，会因为某个任务异常而导致后续任务不执行
        // Web基础漏洞扫描
        // jsoncsrf的检测
//        tasks.add(new JsonCsrf(helpers, callbacks, log, messageInfo));
        // CORS 跨域请求
//        tasks.add(new Cors(helpers, callbacks, log, messageInfo));
        // 未授权访问, 误报太多, 待改进
//        tasks.add(new IDOR(helpers, callbacks, log, messageInfo));
        // 横纵向越权, 纵向越权一般是测试管理后台的时候
//        tasks.add(new IDOR_xy(helpers, callbacks, log, messageInfo));
        // jsonp
//        tasks.add(new Jsonp(helpers, callbacks, log, messageInfo));
        // secure headers
//        tasks.add(new SecureHeader(helpers, callbacks, log, messageInfo));
        // Redirect
//        tasks.add(new Redirect(helpers, callbacks, log, messageInfo));
        // cookie安全属性
//        tasks.add(new SecureCookie(helpers, callbacks, log, messageInfo));
        // https
//        tasks.add(new Https(helpers, callbacks, log, messageInfo));
        // index of 目录浏览
//        tasks.add(new IndexOf(helpers, callbacks, log, messageInfo));
        // 绕过鉴权
//        tasks.add(new BypassAuth(helpers, callbacks, log, messageInfo));
        // TODO 敏感路径扫描
        // SQL注入探测，只做特殊字符的探测，有可疑响应则提醒做手工测试
        tasks.add(new SqlInject(helpers, callbacks, log, messageInfo));
        // 反射型XSS探测
//        tasks.add(new XssReflect(helpers, callbacks, log, messageInfo));
        // TODO 文件上传漏洞，如目录穿越、敏感文件后缀
        // TODO 敏感信息监测，如手机号、身份证、邮箱、userid等
        // TODO bean注入探测，也就是参数爆破啦，不过这个参数不是预制的，而是根据应用抓出来的，所以这个任务不在缓存控制，会一直重复
        // TODO 配合bean注入探测，需要有个分析并收集参数字段的任务
        // TODO ssrf检测（两种情况：绝对url/相对url）
        //      1.检测请求的参数，是否带有url的参数，
        //      - 检查key，如url/source等，
        //      - 检查参数值是否url的格式
        //      2.然后篡改为别的域名的地址

        // 漏洞检测任务，需要调整到cve漏洞扫描模块
        // 每个域名只检查一次
        if (!vulsChecked.contains(urlo.getHost() + urlo.getPort())) {
            // tomcat put jsp //废弃不要了
//            tasks.add(new PutJsp(helpers, callbacks, log, messageInfo));
            // LandrayOa
//            tasks.add(new LandrayOa(helpers, callbacks, log, messageInfo));

            //检测过则添加标记
            vulsChecked += "_" + urlo.getHost() + urlo.getPort();
        }

        //循环执行所有任务，当某个任务异常也不会干扰其他任务执行
        for (VulTaskImpl task :
                tasks) {
            try {
                task.run();
            }catch (Exception e) {
                callbacks.printError("[Exception] " +task + " : " + e.getMessage());
            }
        }
        //跑完，则存入缓存中
        localCache.put(md5, "in");

//        int lastRow = getRowCount();
//        /*
//         * 1、无结果, row == lastRow
//         * 2、1个或以上结果,row < lastRow
//         * 所以，有添加的时候在通过有添加数据
//         * */
//        if (row < lastRow) {
//            /*
//             * fix：java.lang.IndexOutOfBoundsException: Invalid range
//             * 没有添加数据还通知有数据被添加，会导致setAutoCreateRowSorter排序出现Invalid range异常
//             */
//            //通知所有的listener在这个表格中第firstrow行至lastrow列已经被加入了
//            fireTableRowsInserted(row, lastRow - 1);
//        }
        //通知数据可能变更，刷新全表格数据，该用okhttp异步发包后，没办法同步调用fireTableRowsInserted通知刷新数据，因为一直row=lastRow
        fireTableDataChanged();
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    //通知已刷新表格数据
    public void refreshTable(int row){
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

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
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
            // 选中时显示请求跟响应
            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());
            tabs.addTab("Payload", desViewer.getComponent());
            splitPane.setDividerLocation(200);
            splitPane.setRightComponent(tabs);

            LogEntry logEntry = log.get(logTable.convertRowIndexToModel(row));
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            desViewer.setMessage(logEntry.Desc.getBytes(), false);

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
        return currentlyDisplayedItem.getHttpService();
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
        public final short Status;
        public final String Risk;
        public final String Desc;


        public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String method, short status, String risk, String desc)
        {
            this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Method = method;
            this.Path = path;
            this.Host = host;
            this.Risk = risk;
            this.Desc = desc;
        }
    }

}
