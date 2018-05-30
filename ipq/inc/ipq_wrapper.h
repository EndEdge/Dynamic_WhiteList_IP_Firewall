
#ifndef __PX_IPQ_WRAPPER_H__
#define __PX_IPQ_WRAPPER_H__
#include <netinet/in.h>
extern "C" {
#include <linux/netfilter.h>
#include <libipq.h>
}
#include "stdio.h"
#include "pxmem.h"
#include "showhex.h"
#include "ipq_ip.h"
#include "tns.h"
#include "sys/time.h"
typedef struct PA_CO
{
	unsigned long data;
	char dst[64];
	char src[64];
	unsigned long id;
}pa_co;

/*typedef struct IP_Time
{
	timeval start;
	timeval end;
}Ip_Time;*/

typedef struct PA_NODE
{
	struct PA_CO packet_content;
	timeval start_time;
	struct PA_NODE *next;
}Pa_Node;

typedef struct IP_QUEUE
{
	struct PA_NODE *pa_node;
	struct IP_QUEUE *next;
}Ip_Queue;

namespace ipq
{
	class IPQ
	{
	private:
		IPQ( const IPQ& other );
		IPQ& operator = (const IPQ& other );
		static int IPQ_READ_TIMEOUT;
		
	private:
		struct ipq_handle* m_hipq; 
		px::MemBlk m_buf;

		unsigned long m_pack_id;
		ipq_packet_msg_t* m_ppacket;
		bool m_bisvalid;	

		void _reset(void);

	protected:
		void AcceptPacket(ipq_packet_msg_t* pp);
		void DropPacket(void);
		void ShowPacketContent( ipq_packet_msg_t* pp );
		/**/
		virtual void OnPacket( ipq_packet_msg_t* pp );
		/**/
	public:
		IPQ( u_int32_t flags = 0, \
			u_int32_t protocol = AF_INET, \
			u_int32_t mode = IPQ_COPY_META, \
			size_t bufsz = 1024);
		bool m_blog;
		int m_mode;
		int m_dbver;

		inline bool operator!(void)const{ return NULL == m_hipq; }

		bool Perform(void);
		bool SendPacket(void);
		bool Perform1(void);
		bool DePacket(void);

		// return true if the packet should be accepted, false for dropped.
		virtual bool OnFilterContent( const std::string& strSourceIP,\
									  const unsigned short SourcePort, \
									  const std::string& strDestIP, \
									  const unsigned short DestPort, \
									  const void * pdata, \
									  const size_t data_len );

		virtual ~IPQ(void);
	}; // class IPQ
}; // namespace ipq

#endif // __PX_IPQ_WRAPPER_H__

