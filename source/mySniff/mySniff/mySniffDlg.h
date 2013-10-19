
// mySniffDlg.h : ͷ�ļ�
//

#pragma once
#include "stdafx.h"
#include "resource.h"
#include "pcap.h"

// CmySniffDlg �Ի���
class CmySniffDlg : public CDialogEx
{
// ����
public:
	CmySniffDlg(CWnd* pParent = NULL);	// ��׼���캯��
// �Ի�������
	enum { IDD = IDD_MYSNIFF_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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


typedef struct mac_address{  //����mac��ַ����
	u_char byte1;   
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

typedef struct ip_address{ //����ip��ַ����
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct mac_header{ //����macͷ������
	mac_address src;		//Դ��ַ
	mac_address des;		//Ŀ�ĵ�ַ
	u_short type;			//������������ݰ�����
}mac_header;

typedef struct arp_header{ //arp��ͷ������
	u_short mac;			//Ӳ������
	u_short protocol;		//Э������
	u_char maclen;			//Ӳ����ַ����
	u_char protocollen;		//Э���ַ����
	u_short op;				//op
	mac_address macsrc;		//Դ��mac��ַ
	ip_address ipsrc;		//Դ��ip��ַ
	mac_address macdes;		//Ŀ�Ķ���̫����ַ
	ip_address ipdes;		//Ŀ�Ķ�ip��ַ
}arp_header;

typedef struct ip_header{
    u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char  tos;            // ��������(Type of service) 
    u_short tlen;           // �ܳ�(Total length) 
    u_short identification; // ��ʶ(Identification)
    u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char  ttl;            // ���ʱ��(Time to live)
    u_char  proto;          // Э��(Protocol)
    u_short crc;            // �ײ�У���(Header checksum)
    ip_address  saddr;      // Դ��ַ(Source address)
    ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
    u_int   op_pad;         // ѡ�������(Option + Padding)
}ip_header;

typedef struct udp_header{
    u_short sport;          // Դ�˿�(Source port)
    u_short dport;          // Ŀ�Ķ˿�(Destination port)
    u_short len;            // UDP���ݰ�����(Datagram length)
    u_short crc;            // У���(Checksum)
}udp_header;

typedef struct icmp_header{
	u_char type;			//����
	u_char code;			//����
	u_short crc;			//�����
}icmp_header;

typedef struct tcp_header{
	u_short sport;			//Դ�˿ں�
	u_short dport;			//Ŀ�Ķ˿ں�
	u_long index;			//���
	u_long ack;				//ȷ�Ϻ�
	u_short unknown;		//����ͷ���ȵ���Ϣ
	u_short window;			//���ڴ�С
	u_short check_sum;		//�����
	u_short urgent_pointer; //����ָ��
}tcp_header;





