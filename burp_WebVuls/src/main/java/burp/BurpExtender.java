package burp;

import burp.util.JarFileReader;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static burp.BurpExtender.callbacks;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IMessageEditor pocViewer;
    public static final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    private JPanel contentPane;
    public static IMessageEditor editRequestViewer; //发送过来的request
    private Table logTable; //视图table对象
    private JComboBox comboBox;
    private JComboBox comboBoxCve;
    public static IHttpRequestResponse messageInfo;
    // TODO 每次添加新的漏洞时，这里添加对应数据，type为对应的类名，cves为对应漏洞的方法名
    private final String[] type = {"Struts", "FastJson", "Weblogic"};
    private final String[][] cves = {{"all", "CVE_2019_0230"},
                                {"all","dnslogCheck", "JdbcRowSetImpl_0","JdbcRowSetImpl_1","JdbcRowSetImpl_2","JdbcRowSetImpl_3","JdbcRowSetImpl_4",
                                        "TemplatesImpl_0", "TemplatesImpl_1","BasicDataSource_0","BasicDataSource_1",
                                        "JndiDataSourceFactory","SimpleJndiBeanFactory"},
            {"all", "CVE_2020_14882_14883_1", "CVE_2020_14882_14883_xml"}};

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //回调对象
        BurpExtender.callbacks = callbacks;
        //获取扩展helper与stdout对象
        BurpExtender.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName("WebVuls");
        callbacks.registerContextMenuFactory(this);

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
                //type的下拉框
                JLabel typeJ = new JLabel("Type:");
                comboBox = new JComboBox(type);
                comboBox.setToolTipText("what‘s type");
                //对应type的cve下拉框
                JLabel cve = new JLabel("CVE:");
                comboBoxCve = new JComboBox(cves[0]);
                comboBoxCve.setToolTipText("what‘s cve");
                // 为组合框的选择动作注册监听事件,当此组合框的选择有变化时,另一个组合框自动更新内容
                comboBox.addActionListener(e -> {
                    comboBoxCve.removeAllItems();
                    int index = comboBox.getSelectedIndex();
                    for(int i=0; i<cves[index].length; i++) {

                        comboBoxCve.addItem(cves[index][i]);
                    }
                });
                comboBoxCve.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        switch (e.getStateChange())
                        {
                            case ItemEvent.SELECTED:
                                String type = Objects.requireNonNull(comboBox.getSelectedItem()).toString();
                                String cve_str = Objects.requireNonNull(comboBoxCve.getSelectedItem()).toString();
                                String poc = "";
                                try{
                                    Class clazz = Class.forName("burp.vuls." + type);
                                    // 获取对应漏洞的poc
                                    Field pocField = clazz.getField(cve_str + "_poc");
                                    poc = (String) pocField.get(null);
                                }catch (ClassNotFoundException | IllegalAccessException | NoSuchFieldException er){
                                    OutputStream out = callbacks.getStderr();
                                    PrintWriter p = new PrintWriter(out);
                                    er.printStackTrace(p);
                                    try {
                                        p.flush();
                                        out.flush();
                                    } catch (IOException ioException) {
                                        ioException.printStackTrace();
                                    }
                                }
                                pocViewer.setMessage(poc.getBytes(), false);
                                break;
//                            case ItemEvent.DESELECTED:
//                                callbacks.printOutput("DESELECTED " + (String) e.getItem());
//                                break;
                            }
                    }
                });
                panel.add(typeJ);
                panel.add(comboBox);
                panel.add(cve);
                panel.add(comboBoxCve);

                JButton btnConn = new JButton("Start");
                btnConn.setToolTipText("start checking payload");
                btnConn.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.Start();
                    }
                });
                panel.add(btnConn);

                JButton btnClear = new JButton("Clear");
                btnClear.setToolTipText("clear all the result.");
                btnClear.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.ClearResult();
                    }
                });
                panel.add(btnClear);

                JLabel lbConnectInfo = new JLabel("注: 尽量不要选择all，太多任务的话会卡死.");
                lbConnectInfo.setForeground(new Color(255, 0, 0));
                panel.add(lbConnectInfo);

                //左结果面板的ui
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable); //滚动条

                // 右poc设置及request/response面板
                JPanel rJpanel = new JPanel();
                rJpanel.setBorder(new EmptyBorder(5, 5, 5, 5));
                rJpanel.setLayout(new BorderLayout(0, 0));
                editRequestViewer = callbacks.createMessageEditor(BurpExtender.this, true);
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                pocViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                JTabbedPane editTabs = new JTabbedPane();
                editTabs.addTab("Positions", editRequestViewer.getComponent());
                editTabs.addTab("Request", requestViewer.getComponent());
                editTabs.addTab("Response", responseViewer.getComponent());
                editTabs.addTab("Poc", pocViewer.getComponent());
                // 按钮UI
                JPanel rJpanelb = new JPanel();
                BoxLayout boxLayout = new BoxLayout(rJpanelb, BoxLayout.Y_AXIS);
                rJpanelb.setLayout(boxLayout);
                JButton rtnClear = new JButton("add$");
                rtnClear.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        byte[] selectData = editRequestViewer.getSelectedData();
                        byte[] newData = new String(editRequestViewer.getMessage()).replace(new String(selectData), "$poc$").getBytes();
                        editRequestViewer.setMessage(newData, true);
                    }
                });
                JButton rtnClear1 = new JButton("clear$");
                rtnClear1.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        editRequestViewer.setMessage(messageInfo.getRequest(), true);
                    }
                });
                JButton loadClear1 = new JButton("load$");
                loadClear1.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String cve = Objects.requireNonNull(comboBoxCve.getSelectedItem()).toString();
                        JarFileReader jsr = new JarFileReader();
                        String payload = jsr.read(cve + ".tpl");
                        byte[] selectData = editRequestViewer.getSelectedData();
                        byte[] newData = new String(editRequestViewer.getMessage()).replace(new String(selectData), payload).getBytes();
                        editRequestViewer.setMessage(newData, true);
                    }
                });
                JButton refreshClear1 = new JButton("Refresh$");
                refreshClear1.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        byte[] newData = new String(editRequestViewer.getMessage()).getBytes();
                        editRequestViewer.setMessage(newData, true);
                    }
                });
                rJpanelb.add(new JPanel());
                rJpanelb.add(rtnClear);
                rJpanelb.add(rtnClear1);
                rJpanelb.add(loadClear1);
                rJpanelb.add(refreshClear1);
                rJpanelb.add(new JLabel("   "));
                rJpanelb.add(new JLabel("   "));
                // 组装
                rJpanel.add(editTabs, BorderLayout.CENTER);
                rJpanel.add(rJpanelb, BorderLayout.EAST);

                // 设置左结果面板，右request设置面板
                JSplitPane splitPaneAll = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); //左右分割
                splitPaneAll.setDividerLocation(500);
                splitPaneAll.setLeftComponent(scrollPane);
                splitPaneAll.setRightComponent(rJpanel);

                //整个UI就是下面这两部分
                //添加设置的UI到总UI
                contentPane.add(panel, BorderLayout.NORTH);
                //添加结果UI到总UI
                contentPane.add(splitPaneAll, BorderLayout.CENTER);

                //定制UI组件
                callbacks.customizeUiComponent(contentPane);
                callbacks.customizeUiComponent(panel);
//                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(editTabs);

                //添加标签
                callbacks.addSuiteTab(BurpExtender.this);

                //加载插件输出默认信息
                String author = "alumm0x";

                callbacks.printOutput("#Author: "+author);
//                callbacks.printOutput("#Task: JsonCsrfAndCors");

                //注册监听器
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });

    }
    private void Start(){
        //启动检测，根据需要检测的内容,通过反射的方式
        String type = Objects.requireNonNull(comboBox.getSelectedItem()).toString();
        String cve = Objects.requireNonNull(comboBoxCve.getSelectedItem()).toString();
        try{
            Class clazz = Class.forName("burp.vuls." + type);
            // 检测所有漏洞
            if (cve.equalsIgnoreCase("all")){
                //获取本类的所有方法，存放入数组
                Method[] methods = clazz.getDeclaredMethods();
                for (Method method : methods) {
                    // 获取需要检测的漏洞对应的方法并执行
                    method.invoke(null);
                }
            }else {
                // 获取需要检测的漏洞对应的方法并执行
                Method method = clazz.getMethod(cve);
                method.invoke(null);
            }
        }catch (ClassNotFoundException | NoSuchMethodException | InvocationTargetException | IllegalAccessException e){
            OutputStream out = callbacks.getStderr();
            PrintWriter p = new PrintWriter(out);
            e.printStackTrace(p);
            try {
                p.flush();
                out.flush();
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
        fireTableDataChanged();
    }
    //清空数据
    private void ClearResult(){
        log.clear();
        //通知表格数据变更了
        fireTableDataChanged();
    }

    // 这个方法就是插件添加到菜单中
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>(1);
        IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
        messageInfo = requestResponses[0];
        JMenuItem menuItem = new JMenuItem("Send to WebVuls");
        menus.add(menuItem);

        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 添加目标请求数据到编辑框
                editRequestViewer.setMessage(messageInfo.getRequest(), true);
            }
        });
        return menus;
    }


    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    }


    public String getTabCaption() {
        return "WebVuls";
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
            pocViewer.setMessage(logEntry.Poc.getBytes(), false);

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
        return 4;
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
                return "Url";
            case 2:
                return "CVE";
            case 3:
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
                    return logEntry.Url;
                case 2:
                    return logEntry.CVE;
                case 3:
                    return logEntry.Risk;
                default:
                    return "";
            }
        }else {
            return "";
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    //存在漏洞的url信息类
    //log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
    //                            host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
    public static class LogEntry
    {
        public final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        public final String Url;
        public final String CVE;
        public final String Poc;
        public final String Risk;


        public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String url, String cve, String poc, String risk)
        {
            this.id = id;
            this.requestResponse = requestResponse;
            this.Url = url;
            this.CVE = cve;
            this.Poc = poc;
            this.Risk = risk;
        }

    }

}
