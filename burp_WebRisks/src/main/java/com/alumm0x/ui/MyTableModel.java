package com.alumm0x.ui;

import javax.swing.table.AbstractTableModel;


public class MyTableModel extends AbstractTableModel {

    //上面板结果的数量，log是存储检测结果的
    @Override
    public int getRowCount()
    {
        return MainPanel.log.size();
    }
    //结果面板的字段数量
    @Override
    public int getColumnCount()
    {
        return 7;
    }

    //获取数据到面板展示
    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        // 解决setAutoCreateRowSorter排序后,获取row乱了,导致获取表中数据时出现异常
        LogEntry logEntry = MainPanel.log.get(MainPanel.logTable.convertRowIndexToModel(rowIndex));
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
                    return logEntry.Plugin;
                case 6:
                    return logEntry.Risk;
                default:
                    return "";
            }
        }else {
            return "";
        }
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
                return "Plugin";
            case 6:
                return "Risk";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int column) {
        switch (column) {
            case 0:
                return int.class;
            case 1:
            case 2:
            case 3:
            case 5:
            case 6:
                return String.class;
            case 4:
                return short.class;
            default:
                return Object.class;
        }
    }
    
}
