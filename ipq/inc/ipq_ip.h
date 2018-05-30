/*
 *	ipq_ip.h
 *	Peter Xu @ 10/04/2008
 */

#ifndef __IPQ_IP_H__
#define __IPQ_IP_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

namespace ipq
{
	struct IPHeader
	{
		unsigned short IHL:4;
		unsigned short version:4;
		unsigned short TOS:8;
		unsigned short TotalLen;
		unsigned short ID;
		unsigned short FragmentOff:13;
		unsigned short Flags:3;
		unsigned char  TimeToLive;
		unsigned char  Protocol;
		unsigned short CheckSum;
		unsigned int  SourceAddr;
		unsigned int  DestAddr;
	}; // struct IPHeader

	template< typename CharT, typename traits >
	std::basic_ostream<CharT, traits>& operator << ( \
	std::basic_ostream<CharT, traits>& os, const struct IPHeader& iph )
	{
		using namespace std;
		
		char _szBuf[INET_ADDRSTRLEN];

		os << "Version=" << (int)(iph.version) << ":";
		os << "IHL=" << (int)(iph.IHL) << ":";
		os << "TOS=" << (int)(iph.TOS) << ":";
		os << "TotalLength=" << (int)(ntohs(iph.TotalLen)) << ":";
		os << "ID=" << (int)(ntohs(iph.ID)) << ":";
		os << "Flags=" << (int)(iph.Flags) << ":";
		os << "FragmentOff=" << (int)(iph.FragmentOff) << ":";
		os << "TimeToLive=" << (int)(iph.TimeToLive) << ":";
		os << "Protocol=" << (int)(iph.Protocol) << ":";
		os << "CheckSum=" << (int)(ntohs(iph.CheckSum)) << ":";
		
		os << "Source=";
		if ( NULL != inet_ntop( AF_INET, &iph.SourceAddr,_szBuf, sizeof( _szBuf ) ) )
		{
			os << _szBuf;
		}
		else
		{
			os << iph.SourceAddr;
		}
		os << ":";

		os << "Dest=";
		if ( NULL != inet_ntop( AF_INET, &iph.DestAddr,_szBuf, sizeof( _szBuf ) ) )
		{
			os << _szBuf;
		}
		else
		{
			os << iph.DestAddr;
		}
		os << ":";

		os << std::endl;
		
		return os;
	}

  typedef struct tcp_pseudo //定义TCP伪首部 
  { 
   unsigned long src_addr; //源地址 
   unsigned long dst_addr; //目的地址 
   char zero; 
   char proto; //协议类型 
   unsigned short length; //TCP长度 
  }PSD_HEADER; 

	struct TCPHeader
	{
		unsigned short SourcePort;
		unsigned short DestPort;
		unsigned int   SequenceNum;
		unsigned int   AcknowlegeNum;
		unsigned short Reserved:4;
		unsigned short DataOffset:4;
		unsigned short fin:1;
		unsigned short syn:1;
		unsigned short rst:1;
		unsigned short psh:1;
		unsigned short ack:1;
		unsigned short urg:1;
		unsigned short ece:1;
		unsigned short cwr:1;
		unsigned short Window;
		unsigned short CheckSum;
		unsigned short UrgentPointer;
		//unsigned int   Opt;
	}; // struct TCPHeader

	template< typename CharT, typename traits >
	std::basic_ostream<CharT, traits>& operator << ( \
	std::basic_ostream<CharT, traits>& os, const struct TCPHeader& tcph )
	{
		using namespace std;
		os << "Source_Port=" << (unsigned int)(ntohs(tcph.SourcePort)) << ":";
		os << "Dest_Port=" << (unsigned int)(ntohs(tcph.DestPort)) << ":";
		os << "Sequence_Number=" << ntohl(tcph.SequenceNum) << ":";
		os << "Acknowlege_Number=" << ntohl(tcph.AcknowlegeNum) << ":";
		os << "Data_Offset=" << (unsigned int)(tcph.DataOffset) << ":";
		os << "FIN=" << (tcph.fin?'1':'0') << ":";
		os << "SYN=" << (tcph.syn?'1':'0') << ":";
		os << "RST=" << (tcph.rst?'1':'0') << ":";
		os << "PSH=" << (tcph.psh?'1':'0') << ":";
		os << "ACK=" << (tcph.ack?'1':'0') << ":";
		os << "URG=" << (tcph.urg?'1':'0') << ":";
		os << "ECE=" << (tcph.ece?'1':'0') << ":";
		os << "CWR=" << (tcph.cwr?'1':'0') << ":";
		os << "Window=" << (unsigned int)(ntohs(tcph.Window)) <<":";
		os << "CheckSum=" << (unsigned int)(ntohs(tcph.CheckSum)) << ":";
		os << "Urgent_Pointer=" << (unsigned int)(ntohs(tcph.UrgentPointer)) << ":";
	//	os << "Option=" << ntohl( tcph.Opt );
		os << endl;
		return os;
	}
}; // namespace ipq

#endif // __IPQ_IP_H__

