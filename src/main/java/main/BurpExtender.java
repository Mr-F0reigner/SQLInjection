package main;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;

    private final List<LogEntry> masterLog = new CopyOnWriteArrayList<>();
    private final List<LogEntry> detailLog = new CopyOnWriteArrayList<>();
    private final Set<String> processedHashes = Collections.synchronizedSet(new HashSet<>());
    private final ExecutorService executor = Executors.newFixedThreadPool(10);

    // --- 强制布局常量 ---
    private final int FIXED_WIDTH = 260;

    // --- 全局逻辑变量 ---
    private int switchs = 1;
    private int clicks_Repeater = 1;
    private int clicks_Proxy = 1;
    private int is_int = 1;
    private int JTextArea_int = 0;
    private int diy_payload_1 = 1;
    private int diy_payload_2 = 0;
    private int diy_error_switch = 1;
    private int diy_ignore_switch = 0; // 默认关闭忽略报文
    private int white_switchs = 0;
    private String white_URL = "";
    private boolean checkCookie = false;

    // --- UI 组件 ---
    private JSplitPane splitPane;
    private MasterTableModel masterModel;
    private DetailTableModel detailModel;
    private JTable masterTable;
    private JTable detailTable;
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JTextArea log_text;
    private JTextArea payload_jta;
    private JTextArea diy_error_jta;
    private JTextArea diy_ignore_jta;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("SQLInjection");
        api.userInterface().registerSuiteTab("SQL Injection", createUi());
        api.http().registerHttpHandler(new MyHttpHandler());
        String loadSuccess = """
                ========================================================================
                  __  __            _____ ___           _                      \s
                 |  \\/  |_ __      |  ___/ _ \\ _ __ ___(_) __ _ _ __   ___ _ __\s
                 | |\\/| | '__|     | |_ | | | | '__/ _ \\ |/ _` | '_ \\ / _ \\ '__|
                 | |  | | |     _  |  _|| |_| | | |  __/ | (_| | | | |  __/ |  \s
                 |_|  |_|_|    (_) |_|   \\___/|_|  \\___|_|\\__, |_| |_|\\___|_|  \s
                                                          |___/                \s
                [ SQLInjection v1.1 ] - [ LOAD SUCCESS! ]
                - Author: Mr.F0reigner
                - GitHub: https://github.com/Mr-F0reigner/SQLInjection
                ========================================================================
                """;
        api.logging().logToOutput(loadSuccess);
    }

    private Component createUi() {
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane leftVerticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane configVerticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 1. 数据表格初始化
        masterModel = new MasterTableModel();
        masterTable = new JTable(masterModel);
        detailModel = new DetailTableModel();
        detailTable = new JTable(detailModel);

        StatusCellRenderer renderer = new StatusCellRenderer();
        for (int i = 0; i < masterTable.getColumnCount(); i++) masterTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        for (int i = 0; i < detailTable.getColumnCount(); i++) detailTable.getColumnModel().getColumn(i).setCellRenderer(renderer);

        masterTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        setColumnWidth(masterTable, 0, 35, 35, 45);
        setColumnWidth(masterTable, 1, 70, 70, 85);
        setColumnWidth(masterTable, 3, 60, 60, 80);
        setColumnWidth(masterTable, 4, 80, 80, 100);

        detailTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        setColumnWidth(detailTable, 4, 65, 65, 85);

        JSplitPane tableSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(masterTable), new JScrollPane(detailTable));
        tableSplitPane.setResizeWeight(0.7d);

        // 2. 配置面板
        JPanel jps = new JPanel(new GridBagLayout());
        jps.setPreferredSize(new Dimension(FIXED_WIDTH, 400));
        jps.setMinimumSize(new Dimension(FIXED_WIDTH, 400));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 5, 0, 5);

        gbc.gridy++; gbc.insets = new Insets(0, 0, 10, 0);
        JLabel title = new JLabel("Author: Mr.F0reigner");
        title.setForeground(new Color(255, 102, 0));
        jps.add(title, gbc);

        gbc.gridy++; JCheckBox chkStart = new JCheckBox("启动插件", true); jps.add(chkStart, gbc);
        gbc.gridy++; JCheckBox chkRepeater = new JCheckBox("监控Repeater", true); jps.add(chkRepeater, gbc);
        gbc.gridy++; JCheckBox chkProxy = new JCheckBox("监控Proxy", true); jps.add(chkProxy, gbc);
        gbc.gridy++; JCheckBox chkInt = new JCheckBox("值是数字测试-1、-0", true); jps.add(chkInt, gbc);
        gbc.gridy++; JCheckBox chkCookie = new JCheckBox("测试Cookie"); jps.add(chkCookie, gbc);
        gbc.gridy++; JButton btnClear = new JButton("清空列表"); jps.add(btnClear, gbc);

        gbc.gridy++; gbc.insets = new Insets(3, 5, 0, 5);
        jps.add(new JLabel("域名加白(逗号分隔):"), gbc);

        gbc.gridy++; gbc.insets = new Insets(3, 5, 5, 5);
        JTextField whiteTxt = new JTextField("");
        whiteTxt.setPreferredSize(new Dimension(100, 24));
        jps.add(whiteTxt, gbc);

        gbc.gridy++; gbc.insets = new Insets(0, 5, 5, 5);
        JButton btnWhite = new JButton("启动白名单"); jps.add(btnWhite, gbc);

        gbc.gridy++; gbc.weighty = 1.0;
        jps.add(Box.createVerticalGlue(), gbc);

        JTabbedPane tab_diy = new JTabbedPane();
        tab_diy.setPreferredSize(new Dimension(FIXED_WIDTH, 400));
        tab_diy.setMinimumSize(new Dimension(FIXED_WIDTH, 400));

        // --- Payload ---
        JPanel p_panel = new JPanel(new BorderLayout());
        JPanel p_ctrl = new JPanel(new GridBagLayout());
        GridBagConstraints pc = new GridBagConstraints();
        pc.fill = GridBagConstraints.HORIZONTAL; pc.gridx = 0; pc.gridy = 0; pc.weightx = 1.0; pc.insets = new Insets(0, 5, 0, 5);

        JCheckBox chkCustomPay = new JCheckBox("自定义payload", JTextArea_int == 1);
        JCheckBox chkSpaceEnc = new JCheckBox("空格url编码", diy_payload_1 == 1);
        JCheckBox chkValEmpty = new JCheckBox("参数值置空", diy_payload_2 == 1);
        JButton btnLoadPay = new JButton("加载Payload");

        p_ctrl.add(chkCustomPay, pc); pc.gridy++; p_ctrl.add(chkSpaceEnc, pc); pc.gridy++;
        p_ctrl.add(chkValEmpty, pc); pc.gridy++; p_ctrl.add(btnLoadPay, pc);
        p_ctrl.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        payload_jta = new JTextArea("%df' and sleep(3)%23\n'and '1'='1", 10, 10);
        payload_jta.setEditable(JTextArea_int == 1);
        payload_jta.setBackground(JTextArea_int == 1 ? Color.WHITE : Color.LIGHT_GRAY);
        p_panel.add(p_ctrl, BorderLayout.NORTH); p_panel.add(new JScrollPane(payload_jta), BorderLayout.CENTER);

        // --- Error ---
        JPanel e_panel = new JPanel(new BorderLayout());
        JPanel e_ctrl = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JCheckBox chkErrorMatch = new JCheckBox("开启报错信息匹配", diy_error_switch == 1);
        e_ctrl.add(chkErrorMatch);
        e_ctrl.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        diy_error_jta = new JTextArea("ORA-\\d{5}\nSQL syntax.*?MySQL\nUnknown column\nSQL syntax\njava.sql.SQLSyntaxErrorException\nError SQL:\nSyntax error\n附近有语法错误\njava.sql.SQLException\n引号不完整\nSystem.Exception: SQL Execution Error!\ncom.mysql.jdbc\nMySQLSyntaxErrorException\nvalid MySQL result\nyour MySQL server version\nMySqlClient\nMySqlException\nvalid PostgreSQL result\nPG::SyntaxError:\norg.postgresql.jdbc\nPSQLException\nMicrosoft SQL Native Client error\nODBC SQL Server Driver\nSQLServer JDBC Driver\ncom.jnetdirect.jsql\nmacromedia.jdbc.sqlserver\ncom.microsoft.sqlserver.jdbc\nMicrosoft Access\nAccess Database Engine\nODBC Microsoft Access\nOracle error\nDB2 SQL error\nSQLite error\nSybase message\nSybSQLException", 10, 10);
        diy_error_jta.setEditable(diy_error_switch == 0);
        diy_error_jta.setBackground(diy_error_switch == 1 ? Color.LIGHT_GRAY : Color.WHITE);
        e_panel.add(e_ctrl, BorderLayout.NORTH); e_panel.add(new JScrollPane(diy_error_jta), BorderLayout.CENTER);

        // --- Ignore ---
        JPanel i_panel = new JPanel(new BorderLayout());
        JPanel i_ctrl = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JCheckBox chkIgnoreMatch = new JCheckBox("开启忽略报文匹配", diy_ignore_switch == 1);
        i_ctrl.add(chkIgnoreMatch);
        i_ctrl.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        diy_ignore_jta = new JTextArea("\"error\":\"Bad Request\"\n\"status\":400\nInvalid request\nRequest format error", 10, 10);
        diy_ignore_jta.setEditable(diy_ignore_switch == 0);
        diy_ignore_jta.setBackground(diy_ignore_switch == 1 ? Color.LIGHT_GRAY : Color.WHITE);
        i_panel.add(i_ctrl, BorderLayout.NORTH); i_panel.add(new JScrollPane(diy_ignore_jta), BorderLayout.CENTER);

        tab_diy.addTab("Payload", p_panel);
        tab_diy.addTab("报错特征", e_panel);
        tab_diy.addTab("忽略报文", i_panel);

        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();
        JTabbedPane messageTabs = new JTabbedPane();
        messageTabs.addTab("Request", requestViewer.uiComponent());
        messageTabs.addTab("Response", responseViewer.uiComponent());

        configVerticalSplit.setTopComponent(jps);
        configVerticalSplit.setBottomComponent(tab_diy);
        leftVerticalSplit.setTopComponent(tableSplitPane);
        leftVerticalSplit.setBottomComponent(messageTabs);

        splitPane.setLeftComponent(leftVerticalSplit);
        splitPane.setRightComponent(configVerticalSplit);
        splitPane.setResizeWeight(1.0);

        // --- Listeners ---
        chkErrorMatch.addActionListener(e -> {
            boolean sel = chkErrorMatch.isSelected();
            diy_error_switch = sel ? 1 : 0;
            diy_error_jta.setEditable(!sel);
            diy_error_jta.setBackground(sel ? Color.LIGHT_GRAY : Color.WHITE);
        });
        chkCustomPay.addActionListener(e -> {
            boolean sel = chkCustomPay.isSelected();
            JTextArea_int = sel ? 1 : 0;
            payload_jta.setEditable(sel);
            payload_jta.setBackground(sel ? Color.WHITE : Color.LIGHT_GRAY);
        });
        chkIgnoreMatch.addActionListener(e -> {
            boolean sel = chkIgnoreMatch.isSelected();
            diy_ignore_switch = sel ? 1 : 0;
            diy_ignore_jta.setEditable(!sel);
            diy_ignore_jta.setBackground(sel ? Color.LIGHT_GRAY : Color.WHITE);
        });

        chkStart.addActionListener(e -> switchs = chkStart.isSelected() ? 1 : 0);
        chkRepeater.addActionListener(e -> clicks_Repeater = chkRepeater.isSelected() ? 1 : 0);
        chkProxy.addActionListener(e -> clicks_Proxy = chkProxy.isSelected() ? 1 : 0);
        chkInt.addActionListener(e -> is_int = chkInt.isSelected() ? 1 : 0);
        chkCookie.addActionListener(e -> checkCookie = chkCookie.isSelected());
        chkSpaceEnc.addActionListener(e -> diy_payload_1 = chkSpaceEnc.isSelected() ? 1 : 0);
        chkValEmpty.addActionListener(e -> diy_payload_2 = chkValEmpty.isSelected() ? 1 : 0);
        btnClear.addActionListener(e -> {
            masterLog.clear(); detailLog.clear(); processedHashes.clear();
            masterModel.fireTableDataChanged(); detailModel.fireTableDataChanged();
        });

        masterTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                int row = masterTable.getSelectedRow();
                if (row != -1 && row < masterLog.size()) {
                    LogEntry ent = masterLog.get(row);
                    requestViewer.setRequest(ent.requestResponse.request());
                    responseViewer.setResponse(ent.requestResponse.response());
                    detailModel.updateData(ent.dataHash);
                }
            }
        });
        detailTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                int row = detailTable.getSelectedRow();
                if (row != -1) {
                    LogEntry det = detailModel.getEntryAt(row);
                    if (det != null) {
                        requestViewer.setRequest(det.requestResponse.request());
                        if (det.requestResponse.response() != null) responseViewer.setResponse(det.requestResponse.response());
                    }
                }
            }
        });

        SwingUtilities.invokeLater(() -> {
            tableSplitPane.setDividerLocation(0.7d);
            leftVerticalSplit.setDividerLocation(400);
            configVerticalSplit.setDividerLocation(400);
            splitPane.setDividerLocation(1.0d);
        });

        addToggleDividerSupport(splitPane);
        return splitPane;
    }

    private void setColumnWidth(JTable table, int index, int min, int pref, int max) {
        TableColumn col = table.getColumnModel().getColumn(index);
        col.setMinWidth(min); col.setPreferredWidth(pref); col.setMaxWidth(max);
    }

    private void addToggleDividerSupport(JSplitPane sp) {
        for (Component c : sp.getComponents()) {
            if (c instanceof BasicSplitPaneDivider) {
                for (MouseListener ml : c.getMouseListeners()) c.removeMouseListener(ml);
                c.addMouseListener(new MouseAdapter() {
                    @Override public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                            int total = sp.getWidth();
                            if (total <= 0) total = 1024;
                            int current = sp.getDividerLocation();
                            if (current >= total - sp.getDividerSize() - 20) {
                                sp.setDividerLocation(total - FIXED_WIDTH - sp.getDividerSize());
                            } else {
                                sp.setDividerLocation(total);
                            }
                        }
                    }
                });
            }
        }
    }

    private class MyHttpHandler implements HttpHandler {
        @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r) { return RequestToBeSentAction.continueWith(r); }
        @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived res) {
            if (switchs == 1) {
                ToolType tool = res.toolSource().toolType();
                if ((clicks_Repeater == 1 && tool == ToolType.REPEATER) || (clicks_Proxy == 1 && tool == ToolType.PROXY)) {
                    executor.execute(() -> performScan(HttpRequestResponse.httpRequestResponse(res.initiatingRequest(), res), false, tool.name()));
                }
            }
            return ResponseReceivedAction.continueWith(res);
        }
    }

    private void performScan(HttpRequestResponse base, boolean force, String sourceName) {
        if (base.response() == null) return;
        String url = base.request().url();
        if (url.toLowerCase().matches(".*\\.(jpg|png|gif|css|js|woff|pdf|mp4|ico|svg|jpeg|map)$")) return;
        if (white_switchs == 1 && Arrays.stream(white_URL.split(",")).noneMatch(w -> !w.isEmpty() && url.contains(w))) return;

        // --- 优化1：结构化指纹去重 ---
        String cleanUrl = url.contains("?") ? url.substring(0, url.indexOf("?")) : url;
        String sortedParams = getSortedParamKeys(base.request());
        String hash = calculateMd5(base.request().method() + cleanUrl + sortedParams);

        if (!force && processedHashes.contains(hash)) return;
        processedHashes.add(hash);

        int masterId = masterLog.size();
        LogEntry masterEntry = new LogEntry(masterId, base, "run……", hash, sourceName);
        masterLog.add(masterEntry);
        SwingUtilities.invokeLater(() -> masterModel.fireTableDataChanged());

        List<Pattern> rules = new ArrayList<>();
        if (diy_error_switch == 1) {
            rules = Arrays.stream(diy_error_jta.getText().split("\n")).filter(r -> !r.trim().isEmpty()).map(r -> Pattern.compile(r, Pattern.CASE_INSENSITIVE)).collect(Collectors.toList());
        }

        List<Pattern> ignoreRules = new ArrayList<>();
        if (diy_ignore_switch == 1) {
            ignoreRules = Arrays.stream(diy_ignore_jta.getText().split("\n")).filter(r -> !r.trim().isEmpty()).map(r -> Pattern.compile(r, Pattern.CASE_INSENSITIVE)).collect(Collectors.toList());
        }

        for (ParsedHttpParameter param : base.request().parameters()) {
            if (param.type() == HttpParameterType.URL || param.type() == HttpParameterType.BODY || param.type() == HttpParameterType.JSON || (checkCookie && param.type() == HttpParameterType.COOKIE)) {
                List<String> payloads = new ArrayList<>(Arrays.asList("'", "''"));
                if (is_int == 1 && param.value().matches("\\d+")) { payloads.add("-1"); payloads.add("-0"); }
                if (JTextArea_int == 1) {
                    for (String dp : payload_jta.getText().split("\n")) { if (!dp.trim().isEmpty()) payloads.add(diy_payload_1 == 1 ? dp.replace(" ", "%20") : dp); }
                }
                for (String p : payloads) {
                    String finalVal = (diy_payload_2 == 1 && JTextArea_int == 1 && !Arrays.asList("'", "''", "-1", "-0").contains(p)) ? p : param.value() + p;
                    HttpRequest attackReq = base.request().withUpdatedParameters(HttpParameter.parameter(param.name(), finalVal, param.type()));
                    long start = System.currentTimeMillis();
                    HttpRequestResponse attackRes = api.http().sendRequest(attackReq);
                    long duration = System.currentTimeMillis() - start;
                    if (attackRes == null || attackRes.response() == null) continue;
                    String result = analyze(base, attackRes, p, rules, ignoreRules);
                    LogEntry det = new LogEntry(masterId, attackRes, result, hash, sourceName);
                    det.parameter = param.name(); det.payload = finalVal; det.duration = duration;
                    detailLog.add(det);
                    if (!result.equals("Normal")) masterEntry.status = "end! ✔";
                }
            }
        }
        if (!masterEntry.status.contains("✔")) masterEntry.status = "end";
        SwingUtilities.invokeLater(() -> { masterModel.fireTableDataChanged(); detailModel.fireTableDataChanged(); });
    }

    private String analyze(HttpRequestResponse base, HttpRequestResponse attack, String p, List<Pattern> errorRules, List<Pattern> ignoreRules) {
        String body = attack.response().bodyToString();
        // 忽略检测
        if (diy_ignore_switch == 1) {
            for (Pattern pattern : ignoreRules) {
                if (pattern.matcher(body).find()) return "Normal";
            }
        }
        // 报错检测
        if (diy_error_switch == 1) {
            for (Pattern pattern : errorRules) {
                if (pattern.matcher(body).find()) {
                    String r = pattern.pattern();
                    if (r.toLowerCase().contains("mysql") || r.toLowerCase().contains("syntax") || r.contains("ora-") || r.toLowerCase().contains("postgresql")) return "Err: " + r;
                    return "Debug: " + r;
                }
            }
        }
        // Diff 检测
        if (((p.equals("'") || p.equals("-1")) && base.response().body().length() != attack.response().body().length())) return "✔ Diff";
        if (((p.equals("''") || p.equals("-0")) && base.response().body().length() == attack.response().body().length())) return "✔ Recovered";
        return "Normal";
    }

    private String calculateMd5(String in) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] h = md.digest(in.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return String.valueOf(in.hashCode()); }
    }

    private String getParamKeys(HttpRequest req) {
        // 兼容保留
        return getSortedParamKeys(req);
    }

    // --- 新增：参数名排序 ---
    private String getSortedParamKeys(HttpRequest req) {
        List<String> paramNames = new ArrayList<>();
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY || p.type() == HttpParameterType.JSON || (checkCookie && p.type() == HttpParameterType.COOKIE)) {
                paramNames.add(p.name());
            }
        }
        Collections.sort(paramNames);
        return String.join("+", paramNames);
    }

    private static class LogEntry {
        int id; HttpRequestResponse requestResponse; String status, parameter = "", payload = "", dataHash, source;
        long duration = 0;
        LogEntry(int id, HttpRequestResponse rr, String status, String hash, String source) {
            this.id = id; this.requestResponse = rr; this.status = status; this.dataHash = hash; this.source = source;
        }
    }

    private class MasterTableModel extends AbstractTableModel {
        @Override public int getRowCount() { return masterLog.size(); }
        @Override public int getColumnCount() { return 5; }
        @Override public String getColumnName(int c) { return new String[]{"#", "Source", "URL", "Length", "Status"}[c]; }
        @Override public Object getValueAt(int r, int c) {
            LogEntry e = masterLog.get(r);
            return switch(c) {
                case 0 -> e.id; case 1 -> e.source; case 2 -> e.requestResponse.request().url();
                case 3 -> e.requestResponse.response() != null ? e.requestResponse.response().body().length() : 0;
                case 4 -> e.status; default -> "";
            };
        }
    }

    private class DetailTableModel extends AbstractTableModel {
        private final List<LogEntry> displayedDetail = new ArrayList<>();
        public void updateData(String hash) {
            displayedDetail.clear();
            for (LogEntry de : detailLog) { if (de.dataHash != null && de.dataHash.equals(hash)) displayedDetail.add(de); }
            displayedDetail.sort((o1, o2) -> {
                if (o1.status.equals("Normal") && !o2.status.equals("Normal")) return 1;
                if (!o1.status.equals("Normal") && o2.status.equals("Normal")) return -1;
                return 0;
            });
            fireTableDataChanged();
        }
        public LogEntry getEntryAt(int row) { return (row >= 0 && row < displayedDetail.size()) ? displayedDetail.get(row) : null; }
        @Override public int getRowCount() { return displayedDetail.size(); }
        @Override public int getColumnCount() { return 6; }
        @Override public String getColumnName(int c) { return new String[]{"Param", "Payload", "Length", "Diff", "Time", "Status"}[c]; }
        @Override public Object getValueAt(int r, int c) {
            LogEntry e = getEntryAt(r); if (e == null) return "";
            return switch(c) {
                case 0 -> e.parameter; case 1 -> e.payload;
                case 2 -> e.requestResponse.response() != null ? e.requestResponse.response().body().length() : 0;
                case 3 -> e.status.equals("Normal") ? "" : e.status;
                case 4 -> e.duration + "ms"; case 5 -> e.requestResponse.response().statusCode();
                default -> "";
            };
        }
    }

    private class StatusCellRenderer extends DefaultTableCellRenderer {
        private final Color BURP_SEL = new Color(0, 120, 215, 80);
        @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean is, boolean hf, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, is, hf, r, c);
            String st = "";
            if (t.getModel() instanceof DetailTableModel) {
                LogEntry entry = ((DetailTableModel) t.getModel()).getEntryAt(r);
                if (entry != null) st = entry.status;
            } else if (r < masterLog.size()) {
                st = t.getModel().getValueAt(r, 4).toString();
            }
            Color bg = t.getBackground(); Color fg = t.getForeground();
            if (st.startsWith("Err:")) { bg = new Color(255, 204, 204); fg = Color.RED; }
            else if (st.startsWith("Debug:")) { bg = new Color(255, 230, 180); fg = new Color(255, 102, 0); }
            else if (st.contains("✔") || st.contains("end!")) { bg = new Color(204, 255, 204); fg = new Color(0, 128, 0); }
            if (is) { comp.setBackground(mix(bg, BURP_SEL)); comp.setForeground(fg); }
            else { comp.setBackground(bg); comp.setForeground(fg); }
            if (hf) ((JComponent)comp).setBorder(BorderFactory.createEmptyBorder());
            return comp;
        }
        private Color mix(Color c1, Color c2) {
            float a = c2.getAlpha() / 255f;
            return new Color((int)(c1.getRed()*(1-a)+c2.getRed()*a), (int)(c1.getGreen()*(1-a)+c2.getGreen()*a), (int)(c1.getBlue()*(1-a)+c2.getBlue()*a));
        }
    }

}