// mySniffDlg.cpp : ʵ���ļ�
//
#include "stdafx.h"
#include "pcap.h"

#include "mySniff.h"
#include "mySniffDlg.h"
#include "afxdialogex.h"
#include <vector>
#include <string.h>
#include "stdio.h"
#include "conio.h"
using namespace std;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


class SPacketInfo{
public:
	inline SPacketInfo(){};
	inline virtual ~SPacketInfo(){};
	CString time;
	CString len;
	CString srcadd;
	CString desadd;
	CString saddr;
	CString daddr;
	CString protocal;
	CString information;
	CString data;
	CString dataout;
	int type;
	u_long index;
	CString ack;
	char rawdata[1600];
	int rawdatalen;
	u_short realchksum;
};
SPacketInfo PacketInfo;
SPacketInfo PacketSave;
SPacketInfo Packetfile;
CPtrList packet_list;

CCriticalSection g_clsCriticalSection;
u_int netmask;
char p_filter[1024];
char p_search[1024];
char p_seg[1024];
//int saveFile=0;
HWND mainWhandler;
int packetCount=0;
vector <string> vd; 
int nSel;
pcap_if_t *alldevs;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int getDevice();


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	
END_MESSAGE_MAP()


// CmySniffDlg �Ի���




CmySniffDlg::CmySniffDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CmySniffDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_edit_filter = _T("");
	m_edit_search = _T("");
	m_set_seg = _T("");
}

void CmySniffDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_DEVICE_LIST, m_device_list);
	//  DDX_Control(pDX, IDC_LIST, m_list);
	DDX_Control(pDX, IDC_LIST, m_list);
	DDX_Control(pDX, IDC_INFO, m_info);
	DDX_Control(pDX, IDC_STATIC_STATE, m_static);
	//  DDX_Control(pDX, IDC_EDIT_FILTER, m_edit_filter);
	DDX_Text(pDX, IDC_EDIT_FILTER, m_edit_filter);
	DDV_MaxChars(pDX, m_edit_filter, 1024);
	DDX_Text(pDX, IDC_EDIT_SEARCH, m_edit_search);
	DDV_MaxChars(pDX, m_edit_search, 1024);
	DDX_Text(pDX, IDC_EDIT_SEG, m_set_seg);
	DDV_MaxChars(pDX, m_set_seg, 1024);
}

BEGIN_MESSAGE_MAP(CmySniffDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_DEVICE_LIST, &CmySniffDlg::OnSelchangeDeviceList)
//	ON_NOTIFY(NM_CLICK, IDC_LIST, &CmySniffDlg::OnClickList)
	ON_BN_CLICKED(IDC_BEGINCAP, &CmySniffDlg::OnClickedBegincap)
	ON_MESSAGE(WM_MY_MESSAGE, &CmySniffDlg::OnMyMessage)

//	ON_BN_CLICKED(IDC_STOPCAP, &CmySniffDlg::OnBnClickedStopcap)
ON_BN_CLICKED(IDC_SETFILTER, &CmySniffDlg::OnBnClickedSetfilter)
ON_BN_CLICKED(IDC_STOPCAP, &CmySniffDlg::OnBnClickedStopcap)
//ON_EN_CHANGE(IDC_INFO, &CmySniffDlg::OnEnChangeInfo)
//ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST, &CmySniffDlg::OnLvnItemchangedList)
ON_NOTIFY(NM_CLICK, IDC_LIST, &CmySniffDlg::OnClickList)
ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST, &CmySniffDlg::OnCustomdrawList)
ON_BN_CLICKED(IDC_BUTTON4, &CmySniffDlg::OnBnClickedButton4)
//ON_EN_CHANGE(IDC_INFO, &CmySniffDlg::OnEnChangeInfo)
ON_BN_CLICKED(IDC_SEARCH, &CmySniffDlg::OnClickedSearch)
ON_BN_CLICKED(IDC_SET_SEG, &CmySniffDlg::OnClickedSetSeg)
END_MESSAGE_MAP()


// CmySniffDlg ��Ϣ�������

BOOL CmySniffDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�
	
	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	mainWhandler=this->m_hWnd;
	//TRACE("%s",mainWhandler);
	getDevice();
	for(int i=0;i<vd.size();i++){
		CString s(vd[i].c_str());
		TRACE(s);
		m_device_list.AddString(s);
	}
	m_device_list.SetCurSel(0);
	CString ss(vd[0].c_str());
	TRACE(ss);
    SetDlgItemText(IDC_DEVICE,ss);
	//�б��ʼ��
	CRect rect;
	m_list.GetClientRect(&rect);
	m_list.SetExtendedStyle(m_list.GetExtendedStyle()|LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
	m_list.InsertColumn(0,_T("ʱ��"),LVCFMT_CENTER,rect.Width()/10,0);
	m_list.InsertColumn(1,_T("����"),LVCFMT_CENTER,rect.Width()/10,1);
	m_list.InsertColumn(2,_T("Ŀ��MAC��ַ"),LVCFMT_CENTER,rect.Width()/10,2);
	m_list.InsertColumn(3,_T("ԴMAC��ַ"),LVCFMT_CENTER,rect.Width()/10,3);
	m_list.InsertColumn(4,_T("Ŀ��IP��ַ"),LVCFMT_CENTER,rect.Width()/10,4);
	m_list.InsertColumn(5,_T("ԴIP��ַ"),LVCFMT_CENTER,rect.Width()/10,5);
	m_list.InsertColumn(6,_T("Э������"),LVCFMT_CENTER,rect.Width()/10,6);
	m_list.InsertColumn(7,_T("��Ϣ"),LVCFMT_CENTER,rect.Width()*3/10,7);
	

	

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CmySniffDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CmySniffDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CmySniffDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


int getDevice()
{
   // pcap_if_t *alldevs;
    pcap_if_t *d;
	
	string temp;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* ��ȡ���ػ����豸�б� */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
       AfxMessageBox(_T("Error in pcap_findalldevs_ex: %s\n"));
        exit(1);
    }
    
    /* ��ӡ�б� */
    for(d= alldevs; d != NULL; d= d->next)
    {
		string stemp=d->description;
		vd.push_back(stemp);
		i=i+1;
    }
    
    if (i == 0)
    {
        AfxMessageBox(_T("\nNo interfaces found! Make sure WinPcap is installed."));
        return 0;
    }

   
    
}

void CmySniffDlg::OnSelchangeDeviceList()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString device;
	

	nSel=m_device_list.GetCurSel();
	m_device_list.GetLBText(nSel,device);

	SetDlgItemText(IDC_DEVICE, device);
}


USHORT checksum(USHORT *buffer,int size)
 {
	unsigned long cksum=0;
	while(size>1)
 {
    cksum+=*buffer++;
    size-=sizeof(USHORT);
 }
 if(size)
 {
    cksum+=*(UCHAR *)buffer;
 }
 //��32λ��ת����16
 while (cksum>>16)
    cksum=(cksum>>16)+(cksum & 0xffff);
 return (USHORT) (~cksum);
 }

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	
	g_clsCriticalSection.Lock();
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
	mac_header *ma;

	arp_header *arp;
	u_short type;

	u_short mac,protocol,op;
	ip_header *ih;
	u_short total_len,ident,flags,crc;
	u_int ip_len;

	udp_header *uh;
	u_short sport,dport,ulen,ucrc;
	u_char *udp_data;
	int udp_data_len;
	int i;

	icmp_header *icmph;
	u_short icmpcrc;

	tcp_header *th;
	u_short tsport;
	u_short tdport;
	u_long tindex;
	u_long tack;
	u_short tunknown;
	u_short twindow;
	u_short tcheck_sum;
	u_short turgent_pointer;
	u_char *tcp_data;
	int tcp_data_len;
	int j;
	
	int IpDataLength=header->len;
	char IpDataOut[65535]={0};
	CString sdata,turnline;
	sdata.Format(_T("Data In Detail��\r\n"));
	turnline.Format(_T("\n"));
	int end=0;
	if(IpDataLength>0)
	{
		for(int i=0;i<IpDataLength;i++)
		{
			CString dt,s1,s2,s3,s4,s5;
			dt.Format(_T("%02X "),pkt_data[i]);
			if(i%16==15){dt+="\r\n";}
			sdata=sdata+dt;
			if(isgraph(pkt_data[i]))
				IpDataOut[end]=pkt_data[i];
			else if(pkt_data[i]==' ')
				IpDataOut[end]=pkt_data[i];
			else
				IpDataOut[end]='.';
			end=end+1;
		}
	}
	PacketInfo.data=sdata;
	PacketInfo.dataout=IpDataOut;	

				
	ma = (mac_header *)(pkt_data);
    
    //��ʱ���ת���ɿ�ʶ��ĸ�ʽ 
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	TRACE("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

	CString slen;
	slen.Format(_T("%d"),header->len);
	PacketInfo.len=slen;
	TRACE("%d",slen);
	
	CString stime;
	stime.Format(_T("%d:%d:%d"),ltime->tm_hour,ltime->tm_min,ltime->tm_sec);
	PacketInfo.time=stime;
	
	CString src;
	src.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),
		ma->src.byte1,
		ma->src.byte2,
		ma->src.byte3,
		ma->src.byte4,
		ma->src.byte5,
		ma->src.byte6);
	PacketInfo.srcadd=src;
	CString des;
	des.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),
		ma->des.byte1,
		ma->des.byte2,
		ma->des.byte3,
		ma->des.byte4,
		ma->des.byte5,
		ma->des.byte6);
	PacketInfo.desadd=des;


	CString arpsrc,arpdes,arpinfo;
	CString udpinfo,tcpdata,udpdata;
	CString icmpinfo,tcpinfo;
	CString ind, ackn;
	u_char* rawdata;

	ip_header* ip = (ip_header*)(pkt_data+14);
	CString srcaddr;
	srcaddr.Format(_T("%d.%d.%d.%d"),
		ip->saddr.byte1,
		ip->saddr.byte2,
		ip->saddr.byte3,
		ip->saddr.byte4);
	PacketInfo.saddr=srcaddr;

	CString desaddr;
	desaddr.Format(_T("%d.%d.%d.%d"),
		ip->daddr.byte1,
		ip->daddr.byte2,
		ip->daddr.byte3,
		ip->daddr.byte4);
	PacketInfo.daddr=desaddr;

	//����������type���Ի�ø��߲�������İ���Ϣ
	type = ntohs( ma->type );
	switch(type)																		
	{
	case 0x0800:													//ip���ݰ�
		ih = (ip_header *)(pkt_data +14);
		total_len = ntohs( ih -> tlen );
		ident = ntohs( ih ->identification);
		flags = ntohs( ih ->flags_fo);
		crc = ntohs( ih ->crc );
		ip_len = (ih->ver_ihl & 0xf) * 4;
		flags = ntohs(ih->flags_fo);
		if ((flags & 0x1fff) == 0)
	    {
		switch (ih->proto)
		{
			case 17://udp��
				PacketInfo.type=1;
				PacketInfo.protocal="UDP";		
			    uh = (udp_header *) ((u_char*)ih + ip_len);
				//���Ա���udp��������
			    udp_data_len = ntohs(uh ->len) - 8;		
			    udp_data = (u_char*)malloc(udp_data_len + 1);    
			    memcpy(udp_data,((u_char*)uh)+8,udp_data_len);
			    udp_data[udp_data_len] = 0;
				//udp��ͷ����Ϣ
			    sport = ntohs( uh->sport );
			    dport = ntohs( uh->dport );
			    ulen = ntohs( uh->len );
			    ucrc = ntohs( uh->crc );
				
				udpinfo.Format(_T("Դ�˿� %d.-->Ŀ�Ķ˿� %d. �ܳ���Ϊ %d byte. У���Ϊ %#06X."),sport,dport,ulen,ucrc);		
				PacketInfo.information=udpinfo;
				

				for(i=0;i<udp_data_len;i++)								
			    {
				   if (udp_data[i]<=31 || udp_data[i] >=127)
				    {
					    udp_data[i]='.';
				    }
			    }
			    
				//udpdata.Format(_T("%s"),udp_data);
				//PacketInfo.data=udpdata;
				
			    break; 
			case 1://icmp��
				PacketInfo.type=2;
			    PacketInfo.protocal="ICMP";
			    icmph = (icmp_header *) ((u_char*)ih + ip_len);
			    icmpcrc = ntohs( icmph->crc );
				
				icmpinfo.Format(_T("ICMP����: %d. ����: %d. У���: %#06X."),icmph ->type,icmph ->code,icmpcrc);    //icmp��ͷ����Ϣ
			    break;
			case 6://TCP
				PacketInfo.type=3;
		        PacketInfo.protocal="TCP";
		        th = (tcp_header *) ((u_char*)ih + ip_len);
		        tsport = ntohs( th ->sport );
		        tdport = ntohs( th ->dport );
		        tindex = ntohl( th ->index );
		        tack = ntohs( th ->ack );
		        tunknown = ntohs( th ->unknown);
		        twindow = ntohs( th ->window);
		        tcheck_sum = ntohs(th ->check_sum);
		        turgent_pointer = ntohs(th ->urgent_pointer);
				PacketInfo.index = tindex;
				ackn.Format(_T("%d"), tack);
				PacketInfo.ack = ackn;
		        
				tcpinfo.Format(_T("Դ�˿� %d-->Ŀ�Ķ˿� %d. seq:%#010X,ack:%#010X,�ײ�����: %d,URG:%d,ACK:%d,PSH:%d,RST:%d,SYS:%d,FIN:%d,У���:%#X"),tsport,tdport,tindex,tack,(tunknown & 0xf000)>>12,(tunknown & 0x20)>>5,(tunknown & 0x10)>>4,(tunknown & 0x8)>>3,(tunknown & 0x4)>>2,(tunknown & 0x2)>>1,(tunknown & 0x1),tcheck_sum);		//tcp��ͷ����Ϣ
		        PacketInfo.information=tcpinfo;	
			
				tcp_data_len = ntohs(ih ->tlen) - (ih->ver_ihl & 0xf) * 4 - ((tunknown & 0xf000)>>12) ;   //����tcp�������ݵĳ���
			    tcp_data = (u_char*)malloc(tcp_data_len + 1);
			    memcpy(tcp_data,((u_char*)th)+((tunknown & 0xf000)>>12),tcp_data_len);
				rawdata = (u_char*)malloc(tcp_data_len+1);
				memcpy(rawdata, tcp_data, tcp_data_len);
				//AfxMessageBox((LPCWSTR)tcp_data);
				//PacketInfo.rawdata=(char*)malloc(tcp_data_len*sizeof(char));
				TRACE("tcp_data:%s\n",tcp_data);
				memcpy(PacketInfo.rawdata,tcp_data+15,tcp_data_len-15);
				TRACE("pack_info_data:%s\n",PacketInfo.rawdata);
				PacketInfo.rawdatalen = tcp_data_len-15;
			    tcp_data[tcp_data_len] = 0;
			    for(j=0;j<tcp_data_len;j++)			//tcp�������ݲ���
			    {
				    if (tcp_data[j]<=31 || tcp_data[j] >=127)
				    {
					    tcp_data[j]='.';
				    }
			    }
				//tcpdata.Format(_T("%s"),tcp_data);
				//PacketInfo.data=tcpdata;
				PacketInfo.realchksum = checksum((unsigned short *)th,tcp_data_len+sizeof(tcp_header));
				TRACE("checksum:%d\n", tcheck_sum);
				TRACE("realchksum:%d\n", PacketInfo.realchksum);
			    break;
			default:
				break;
		    }
		}
	
		break;
	case 0x0806:
	case 0x8035://ARP
		PacketInfo.type=4;
		PacketInfo.protocal="ARP";
		arp = (arp_header *)(pkt_data+14);
		mac = ntohs( arp->mac );
		protocol = ntohs( arp->protocol );
		op = ntohs( arp->op );

		
		arpsrc.Format(_T("ԴIP��ַ %d.%d.%d.%d ѯ��"),
			arp->ipsrc.byte1,
			arp->ipsrc.byte2,
			arp->ipsrc.byte3,
			arp->ipsrc.byte4);
		
		
		arpdes.Format(_T("Ŀ��IP��ַ:%d.%d.%d.%d ��MAC��ַ"),
			arp->ipdes.byte1,
			arp->ipdes.byte2,
			arp->ipdes.byte3,
			arp->ipdes.byte4);
		
		arpinfo.Format(_T("Ӳ������: %#06X,Э������: %#06X, MAC��ַ����Ϊ%dbyte,Э���ַ����Ϊ%dbyte,������%#06X"),mac,protocol,arp->maclen,arp->protocollen,op);
		PacketInfo.information=arpsrc+arpdes+arpinfo;
		break;
	
		
	default: 
		PacketInfo.type=5;
		PacketInfo.protocal="δ֪����";
		PacketInfo.information="...������Ϣ...";
		break;
	}
	
	g_clsCriticalSection.Unlock();

	//AfxMessageBox(_T("hello"));

	::SendMessage(mainWhandler,WM_MY_MESSAGE,0,0);
		
     
}



DWORD WINAPI pcap(LPVOID pParam)
{
	//pcap_handler Handler;
	//pcap_dumper_t* dumpfile;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	pcap_if_t *d;
	pcap_t *adhandle;
	/* ��ת��ѡ�е������� */
    for(d=alldevs, i=0; i< nSel-1 ;d=d->next, i++);
    
    /* ���豸 */
    if ( (adhandle= pcap_open(d->name,          // �豸��
                              65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
							     PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ȡ��ʱʱ��
                              NULL,             // Զ�̻�����֤
                              errbuf            // ���󻺳��
                              ) ) == NULL)
    {
        AfxMessageBox(_T("Unable to open the adapter. %s is not supported by WinPcap"));
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }
	struct bpf_program fcode;
    char *Interface=NULL;
    if(p_filter!=NULL){
		if (d->addresses != NULL){
         //��ȡ�ӿڵ�һ����ַ������ 
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		}else{
         //�������ӿ�û�е�ַ����ô���Ǽ�������ӿ���C�������� 
        netmask=0xffffff; 
		}
		if (pcap_compile(adhandle,(bpf_program *) &fcode, p_filter, 1, netmask) <0 )
        {
            fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
            // �ͷ��豸�б� 
            pcap_freealldevs(alldevs);
            return -1;
        }
		
       // �����洢�ػ����ݰ����ļ�
      // dumpfile=pcap_dump_open(adhandle, "e:\\test.pcap");  
    
        //���ù�����
        if (pcap_setfilter(adhandle,(bpf_program *) &fcode)<0)
        {
            fprintf(stderr,"\nError setting the filter.\n");
            // �ͷ��豸�б� 
            pcap_freealldevs(alldevs);
            return -1;
        }
	}
   
    
    /* ��ʼ���� */
	
    pcap_loop(adhandle, 0, packet_handler, NULL);
	
    
    return 0;
}


void CmySniffDlg::OnClickedBegincap()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//UpdataData(TRUE);
	CStatic * pStatic=(CStatic *)GetDlgItem(IDC_STATIC_STATE);
	pStatic->SetWindowText(_T("���ڼ����˿�..."));
	
	//AfxBeginThread(pcap,mainWhandler);
	LPDWORD threadCap=NULL;
	m_ThreadHandle=CreateThread(NULL,0,pcap,this,0,threadCap);
	if(m_ThreadHandle==NULL)
	{
		int code=GetLastError();
		CString str;
		str.Format(_T("�����̴߳��󣬴���Ϊ%d."),code);
		MessageBox(str);
	}	
}

afx_msg LRESULT CmySniffDlg::OnMyMessage(WPARAM wParam, LPARAM lParam)
{
	g_clsCriticalSection.Lock();
	SPacketInfo *ptemp;
	ptemp=new SPacketInfo();
	ptemp->data=PacketInfo.data;
	ptemp->time=PacketInfo.time;
	ptemp->desadd=PacketInfo.desadd;
	ptemp->len=PacketInfo.len;
	ptemp->srcadd=PacketInfo.srcadd;
	ptemp->protocal=PacketInfo.protocal;
	ptemp->information=PacketInfo.information;
	ptemp->dataout=PacketInfo.dataout;
	ptemp->type=PacketInfo.type;
	ptemp->daddr=PacketInfo.daddr;
	ptemp->saddr=PacketInfo.saddr;
	ptemp->index=PacketInfo.index;
	ptemp->ack=PacketInfo.ack;
	memcpy(ptemp->rawdata,PacketInfo.rawdata,PacketInfo.rawdatalen);
	ptemp->rawdatalen=PacketInfo.rawdatalen;
	ptemp->realchksum=PacketInfo.realchksum;
	
	packet_list.AddTail(ptemp);	
	
	m_list.InsertItem(packetCount,_T(""));
	m_list.SetItemText(packetCount,0, ptemp->time);
	m_list.SetItemText(packetCount,1, ptemp->len);
	m_list.SetItemText(packetCount,2 , ptemp->desadd);
	m_list.SetItemText(packetCount,3 , ptemp->srcadd);
	m_list.SetItemText(packetCount,4 , ptemp->daddr);
	m_list.SetItemText(packetCount,5 , ptemp->saddr);
	m_list.SetItemText(packetCount,6 , ptemp->protocal);
	m_list.SetItemText(packetCount,7 , ptemp->information);
	g_clsCriticalSection.Unlock();
	//Invalidate();
	packetCount++;
	CString num;
	num.Format(_T("%d"),packetCount);
	CEdit * pEditdata=(CEdit *)GetDlgItem(IDC_NUM);
	pEditdata->SetWindowText(num);
	//AfxMessageBox(_T("hello"));
	return 0;
}


void CmySniffDlg::OnBnClickedSetfilter()
{
	UpdateData(true);
	char *p=p_filter;
	p=(LPSTR)(LPCTSTR)m_edit_filter;
	UpdateData(false);
}


void CmySniffDlg::OnBnClickedStopcap()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CStatic * pStatic=(CStatic *)GetDlgItem(IDC_STATIC_STATE);
	pStatic->SetWindowText(_T("Ҫ�����˿���"));
	if(NULL == this->m_ThreadHandle )
		return;
	if(TerminateThread(this->m_ThreadHandle,-1)==0)
	{
		MessageBox(_T("�ر��̴߳���!"));
		return;
	}
	this->m_ThreadHandle = NULL;

}




void CmySniffDlg::OnClickList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
           if(pNMListView->iItem != -1)
           {
                CString strtemp;
                strtemp.Format(_T("�������ǵ�%d�е�%d��"),
                                pNMListView->iItem, pNMListView->iSubItem);
                
           }
    POSITION po=packet_list.FindIndex(pNMListView->iItem);
    SPacketInfo *tem=(SPacketInfo *)packet_list.GetAt(po);
	
	CEdit * pEditinfo=(CEdit *)GetDlgItem(IDC_INFO);
	pEditinfo->SetWindowText(tem->information);
	PacketSave.data = tem->data;
	PacketSave.dataout = tem->dataout;
	TRACE("%s", PacketSave.data);

    CEdit * pEditdata=(CEdit *)GetDlgItem(IDC_DATAEDIT);
	pEditdata->SetWindowText(tem->data);
	*pResult = 0;

	Packetfile.daddr = tem->daddr;
	Packetfile.saddr = tem->saddr;
	Packetfile.desadd = tem->desadd;
	Packetfile.srcadd = tem->srcadd;
	Packetfile.index = tem->index;
	Packetfile.ack = tem->ack;
}


void CmySniffDlg::OnCustomdrawList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if(CDDS_PREPAINT==pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}else if(CDDS_ITEMPREPAINT ==pNMCD->nmcd.dwDrawStage){
		COLORREF crText;
		char buf[10];
		memset(buf,0,10);
		POSITION pos = packet_list.FindIndex(pNMCD->nmcd.dwItemSpec);
		SPacketInfo *tem=(SPacketInfo *)packet_list.GetAt(pos);
		int flag=tem->type;
		

	    if(flag==1)
			crText = RGB(194,195,252);				
		else if(flag==2)
				crText = RGB(230,230,230);
		else if(flag==3)
				crText = RGB(226,238,227);
		else if(flag==4)
				crText = RGB(49,164,238);
		else if(flag==5)
				crText = RGB(238,232,180);
		

		pNMCD->clrTextBk =crText;
		*pResult = CDRF_DODEFAULT;
	}
 
}

void CmySniffDlg::OnBnClickedButton4()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(true);
    fp.Open(_T("E:\\savedpacket.pcap"),CFile::modeCreate |  CFile::modeWrite);
	fp.WriteString(_T("Packet-->\n"));
	fp.WriteString(PacketSave.data+_T("\r\n"));
	fp.WriteString(PacketSave.dataout+_T("\r\n"));
	fp.Close();
	AfxMessageBox(_T("�����ݰ��ѱ�����E:\\savedpacket.pcap"));  
	UpdateData(false);
}



void CmySniffDlg::OnClickedSearch()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(true);
	char *p=p_search;
	p = (LPSTR)(LPCTSTR)m_edit_search;
	CString cs;
	CString s;
	cs.Format(_T("%s"), p);
	int flag = -1;
	int result = 0;
	fp.Open(_T("E:\\searchresult.pcap"),CFile::modeCreate |  CFile::modeWrite);
	for(int i=0;i<packet_list.GetCount();i++){
		POSITION po = packet_list.FindIndex(i);
		SPacketInfo * tem = (SPacketInfo *)packet_list.GetAt(po);
		CString str = tem->dataout;
		result = str.Find(cs);
		//TRACE("%s",cs);
		if (result!=-1){
			s.Format(_T("PacketNumber:%d"),i);
			fp.WriteString(str+_T("\r\n"));
			fp.WriteString(tem->data+_T("\r\n"));
			fp.WriteString(tem->dataout+_T("\r\n"));
			flag = 1;
		}
	}
	if(flag == 0){
		AfxMessageBox(_T("%s not found!", m_edit_search));
	}else{
		AfxMessageBox(_T("�������������searchresult.pcap!"));
	}
	fp.Close();
	UpdateData(false);
}



void CmySniffDlg::OnClickedSetSeg()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(true);
	char *p=p_seg;
	p = (LPSTR)(LPCTSTR)m_set_seg;
	fp.Open(m_set_seg, CFile::modeCreate |  CFile::modeWrite);
	SPacketInfo * temp;
	TRACE("//%d//", packet_list.GetCount());
	vector <SPacketInfo*> A_list, B_list;	
	for(int i=0;i<packet_list.GetCount();i++){
		POSITION po = packet_list.FindIndex(i);
		SPacketInfo * tem = (SPacketInfo *)packet_list.GetAt(po);
		//TRACE("--%s--\n", tem->rawdata);
		//TRACE("%s==%s==%s==%s\n", Packetfile.daddr, Packetfile.saddr, Packetfile.desadd, Packetfile.srcadd);
		//TRACE("%s~~%s~~%s~~%s\n", tem->daddr, tem->saddr, tem->desadd, tem->srcadd);
		if(strcmp((char*)(LPCTSTR)tem->daddr,(char*)(LPCTSTR)Packetfile.daddr)==0 && strcmp((char*)(LPCTSTR)tem->saddr,(char*)(LPCTSTR)Packetfile.saddr)==0 && strcmp((char*)(LPCTSTR)tem->desadd,(char*)(LPCTSTR)Packetfile.desadd)==0 && strcmp((char*)(LPCTSTR)tem->srcadd,(char*)(LPCTSTR)Packetfile.srcadd)==0){
			A_list.push_back(tem);
		}
		if(strcmp((char*)(LPCTSTR)tem->saddr,(char*)(LPCTSTR)Packetfile.daddr)==0 && strcmp((char*)(LPCTSTR)tem->daddr,(char*)(LPCTSTR)Packetfile.saddr)==0 && strcmp((char*)(LPCTSTR)tem->srcadd,(char*)(LPCTSTR)Packetfile.desadd)==0 && strcmp((char*)(LPCTSTR)tem->desadd,(char*)(LPCTSTR)Packetfile.srcadd)==0){
			B_list.push_back(tem);
		}
	}
	TRACE("��%d, %d��", A_list.size(), B_list.size());
	for(int m=A_list.size()-1; m>0; m--){
		for(int n=0; n<m; n++){
			if(A_list[n]->index > A_list[n+1]->index){
				temp = A_list[n];
				A_list[n] = A_list[n+1];
				A_list[n+1] = temp;
			}
		}
	}
	for(int m=B_list.size()-1; m>0; m--){
		for(int n=0; n<m; n++){
			if(B_list[n]->index > B_list[n+1]->index){
				temp = B_list[n];
				B_list[n] = B_list[n+1];
				B_list[n+1] = temp;
			}
		}
	}
	u_long seqA=0,seqB=0;
	for(int j=0; j<A_list.size(); j++){
		TRACE("A_list index:%d����", A_list[j]->index);
		if(A_list[j]->index!=seqA){
			seqA=A_list[j]->index;
		
		//TRACE("����%s����", A_list[j]->rawdata);
		//MessageBox(A_list[j]->rawdata);
			fp.Write(A_list[j]->rawdata,A_list[j]->rawdatalen);
		//fp.WriteString(A_list[j]->rawdata);
		}
	}
	for(int k=0; k<B_list.size(); k++){
		TRACE("B_list index:%d����", B_list[k]->index);
		if(B_list[k]->index!=seqB){
			seqB=B_list[k]->index;
		//MessageBox(B_list[k]->rawdata);
		//fp.WriteString(B_list[k]->rawdata);
			fp.Write(B_list[k]->rawdata, B_list[k]->rawdatalen);
		}
	}
	AfxMessageBox(_T("�����ļ��ѱ�����")+m_set_seg);
	fp.Close();
	UpdateData(false);
}