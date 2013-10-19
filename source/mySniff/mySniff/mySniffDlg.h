
// mySniffDlg.h : 头文件
//

#pragma once
#include "stdafx.h"
#include "resource.h"
#include "pcap.h"

// CmySniffDlg 对话框
class CmySniffDlg : public CDialogEx
{
// 构造
public:
	CmySniffDlg(CWnd* pParent = NULL);	// 标准构造函数
// 对话框数据
	enum { IDD = IDD_MYSNIFF_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_device_list;
	afx_msg void OnSelchangeDeviceList();
//	CListBox m_list;
	CListCtrl m_list;
//	afx_msg void OnClickList(NMHDR *pNMHDR, LRESULT *pResult);
	CEdit m_info;
	CStdioFile  fp;
	CStatic m_static;
	afx_msg void OnClickedBegincap();
	CMap<DWORD , DWORD& , COLORREF , COLORREF&> MapItemColor;
	HANDLE m_ThreadHandle;
	
protected:
//	afx_msg LRESULT OnMyMessage(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnMyMessage(WPARAM wParam, LPARAM lParam);
public:
//	afx_msg void OnBnClickedStopcap();
//	CEdit m_edit_filter;
	afx_msg void OnBnClickedSetfilter();
	CString m_edit_filter;
	afx_msg void OnBnClickedStopcap();
	afx_msg void OnClickList(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnCustomdrawList(NMHDR *pNMHDR, LRESULT *pResult);
	
	afx_msg void OnBnClickedButton4();
//	afx_msg void OnEnChangeInfo();
	CString m_edit_search;
	afx_msg void OnClickedSearch();
	afx_msg void OnClickedSetSeg();
	CString m_set_seg;
};

DWORD WINAPI pcap(LPVOID pParam);


typedef struct mac_address{  //定义mac地址类型
	u_char byte1;   
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

typedef struct ip_address{ //定义ip地址类型
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct mac_header{ //定义mac头的类型
	mac_address src;		//源地址
	mac_address des;		//目的地址
	u_short type;			//定义网络层数据包类型
}mac_header;

typedef struct arp_header{ //arp包头部类型
	u_short mac;			//硬件类型
	u_short protocol;		//协议类型
	u_char maclen;			//硬件地址长度
	u_char protocollen;		//协议地址长度
	u_short op;				//op
	mac_address macsrc;		//源端mac地址
	ip_address ipsrc;		//源端ip地址
	mac_address macdes;		//目的端以太网地址
	ip_address ipdes;		//目的端ip地址
}arp_header;

typedef struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service) 
    u_short tlen;           // 总长(Total length) 
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

typedef struct icmp_header{
	u_char type;			//类型
	u_char code;			//代码
	u_short crc;			//检验和
}icmp_header;

typedef struct tcp_header{
	u_short sport;			//源端口号
	u_short dport;			//目的端口号
	u_long index;			//序号
	u_long ack;				//确认号
	u_short unknown;		//包括头长度等信息
	u_short window;			//窗口大小
	u_short check_sum;		//检验和
	u_short urgent_pointer; //紧急指针
}tcp_header;





