#define MAX_NUM 3000
#define MAX_QUEUE 20000
#include "ipq_wrapper.h"
#include <iostream>
#include <string.h>
#include <stdlib.h>

pthread_mutex_t mutex;
Ip_Queue *IP_Queue=NULL;
Ip_Queue *De_Queue=NULL;
Pa_Node  *Pa_Queue=NULL;
struct ipq_handle* m_hipq_1 = NULL;
unsigned long WK_SET[MAX_NUM] = {0};
timeval WK_TIME[MAX_NUM];
long total_recv = 0;
long total_send = 0;
int nowsend = 0;
int queue_num = 0;
long queue_num2 = 0;
timeval start_time, end_time;
timeval delay_time;

clock_t startTime,endTime;

namespace ipq
{
	int IPQ::IPQ_READ_TIMEOUT = 0;

	IPQ::IPQ( u_int32_t flags, \
			  u_int32_t protocol, \
			  u_int32_t mode, \
			  size_t bufsz):
	m_hipq( NULL ),
	m_buf( bufsz ),
	m_bisvalid(false),
	m_blog(false),
	m_pack_id(-1),
	m_ppacket( NULL )
	{
		m_hipq = ipq_create_handle( flags, protocol );
		if ( NULL != m_hipq )
		{
			m_hipq_1 = m_hipq;
			int _itmp = ipq_set_mode( m_hipq, mode, bufsz );
			if ( _itmp <= 0 )
			{
				std::cerr << ipq_errstr();
				std::cerr << " ipq_set_mode returned " << _itmp;
				std::cerr << std::endl;
				ipq_destroy_handle( m_hipq );
				m_hipq = NULL;
			}
		}
		else
		{
			std::cerr << ipq_errstr() << std::endl;
		}
		return;
	}

	void IPQ::_reset(void)
	{
		m_bisvalid = 0;
		m_pack_id = -1;
		m_ppacket = NULL;

		return;
	}

	bool IPQ::Perform(void)
	{
		if ( NULL == m_hipq )
		{
			std::cerr << "Null IPQ Handle..";
			return false;
		}
		_reset();
		m_bisvalid = ( ipq_read( m_hipq, m_buf.Offset(), \
					m_buf.Size(), IPQ_READ_TIMEOUT ) > 0 );
		gettimeofday(&start_time,0);
		if ( m_bisvalid )
		{
			m_bisvalid = \
				( NLMSG_ERROR != ipq_message_type( m_buf.Offset() ) );
			if ( m_bisvalid )
			{
                m_ppacket = ipq_get_packet( m_buf.Offset() );
				if ( NULL != m_ppacket )
				{
					m_pack_id = m_ppacket->packet_id;
				}
				else
				{
					_reset();
				}
			}
		}
		
		if ( m_bisvalid )
		{
			OnPacket( m_ppacket );
			return true;
		}
		else
		{
			return false;
		}
	}
       // return true if the packet should be accepted, false for dropped.
	bool IPQ::OnFilterContent( const std::string& strSourceIP,\
		                       const unsigned short SourcePort, \
							   const std::string& strDestIP, \
		                       const unsigned short DestPort, \
		                       const void * pdata, \
			                   const size_t data_len )
	{
		using namespace std;
		cout << strSourceIP << ":" << SourcePort << " => ";
		cout << strDestIP << ":" << DestPort << endl;
		cout << "=Packet1=" << endl;
		
       
		return true;
	}

	void IPQ::ShowPacketContent( ipq_packet_msg_t* pp )
	{
		using namespace std;
		if ( NULL != pp )
		{
			cout << "sizeof(ipq_packet_msg_t)=" << sizeof( *pp) << ":";
			cout << "Packet_ID=" << pp->packet_id <<":";
			cout << "Netfilter_Mark=" << pp->mark <<":";
			cout << "Packet_Arrival_Time(SEC)=" << pp->timestamp_sec <<":";
			cout << "Packet_Arrival_Time(USEC)=" << pp->timestamp_usec<<":";
			cout << "NetFilter_Hook=" << pp->hook <<":";
			cout << "Incoming_Interface=" << "\"" << pp->indev_name << "\":";
			cout << "Outgoing_Interface=" << "\"" << pp->outdev_name << "\":";
			cout << "Hardware_Protocol=" << pp->hw_protocol << ":";
			cout << "Hardware_Type=" << pp->hw_type << ":";
			cout << "Data_Length=" << pp->data_len << endl;
		
			cout << *(IPHeader*)((char*)pp + sizeof( *pp) );
			cout << *(TCPHeader*)((char*)pp + sizeof( *pp) + sizeof( IPHeader) );

			ShowHex( cout, pp, 0, sizeof( ipq_packet_msg_t ) +  pp->data_len);
			
		}
		return;
	}

int inserttail(unsigned long mpacket_id,unsigned long data,char*dst, char*src)
{
	using namespace std;
	Ip_Queue *head=NULL;
	Ip_Queue *tail=NULL;
	Pa_Node *headnode=NULL;
	Pa_Node *tailnode=NULL;
	//double lasttime = 0;
	int hasone = 0;	
	if(IP_Queue==NULL)
	{
		queue_num ++;
		queue_num2 ++;
		IP_Queue = (Ip_Queue*)malloc(sizeof(Ip_Queue));
		if(IP_Queue!=NULL)
		{
			IP_Queue->pa_node =(Pa_Node*)malloc(sizeof(Pa_Node));
        		if(IP_Queue->pa_node!=NULL)
        		{
                	IP_Queue->pa_node->packet_content.id = mpacket_id;
					IP_Queue->pa_node->start_time = start_time;

                	strcpy(IP_Queue->pa_node->packet_content.dst,dst);
                	strcpy(IP_Queue->pa_node->packet_content.src,src);
					IP_Queue->pa_node->packet_content.data = data;
					printf("packet sid is %lu,iii%lu\n",mpacket_id,data);
					IP_Queue->pa_node->next=NULL;
        		}
			IP_Queue->next = NULL;
			ipq_set_verdict( m_hipq_1, mpacket_id, NF_QUEUE,  0, NULL  );
			return 1;
		}
	}
	pthread_mutex_lock(&mutex);
	head = IP_Queue;
	tail = IP_Queue;
	while(head!=NULL && head->next!=NULL) //Find if there are repeated data package
	{		
		if(head->pa_node!=NULL)
		 if( head->pa_node->packet_content.data == data)
		{
			hasone = 1;
			break;
		}

		head=head->next;
	}
	if(head->pa_node!=NULL && head->pa_node->packet_content.data == data)    
		hasone = 1;

	if(!hasone)     //If there isn't any repeated package, insert it into tail of IPQUEUE
	{	
		if(queue_num >= MAX_QUEUE){
			pthread_mutex_unlock(&mutex);
			return 0;
		}
		queue_num ++;
		queue_num2 ++;
		printf("queue_num2 = %ld\n", queue_num2);
		tail = (Ip_Queue*)malloc(sizeof(Ip_Queue));
		if(tail != NULL)
		{
			tail->pa_node = (Pa_Node*)malloc(sizeof(Pa_Node));
			if(tail->pa_node == NULL)
			{
				printf("malloc error------------------\n");
				exit(0);
				return 0;
			}
			if(tail->pa_node!=NULL)
			{
				head->next = tail;
					tail->pa_node->packet_content.id = mpacket_id;
					tail->pa_node->start_time = start_time;
					
					gettimeofday(&delay_time,0);
			printf("cost_time_delay=%lf ms\n",(double)(1000000*(delay_time.tv_sec - start_time.tv_sec) + delay_time.tv_usec - start_time.tv_usec)/1000);


					strcpy(tail->pa_node->packet_content.dst,dst);
					strcpy(tail->pa_node->packet_content.src,src);
					tail->pa_node->packet_content.data = data;
					tail->pa_node->next = NULL;
					tail->next = NULL;
					printf("packet sid is %lu\n",mpacket_id);
					ipq_set_verdict( m_hipq_1, mpacket_id, NF_QUEUE,  0, NULL  );
			}
		}
	}
	else        //If there are replicated package, insert it into the linked list with same data
	{
		printf("Q has one \n");
		headnode = head->pa_node;
		tailnode = head->pa_node;
		while(headnode->next!=NULL)
		{
			headnode = headnode->next;
		}
		tailnode = (Pa_Node*)malloc(sizeof(Pa_Node));
		if(tailnode!=NULL)
		{
			headnode->next = tailnode;
                        tailnode->packet_content.id = mpacket_id;
						tailnode->start_time = start_time;
                        strcpy(tailnode->packet_content.dst,dst);
                        strcpy(tailnode->packet_content.src,src);
                        tailnode->packet_content.data = data;
                        tailnode->next = NULL;
                        printf("packet sid is %lu\n",mpacket_id);
			ipq_set_verdict( m_hipq_1, mpacket_id, NF_QUEUE,  0, NULL  );
		}
	}
	pthread_mutex_unlock(&mutex);
	return 1;
}

int insertDequeue(Ip_Queue *Qnode, Pa_Node *Pnode)
{
	//using namespace std;
	Ip_Queue *Qhead=NULL;
	Pa_Node *Phead=NULL;
	pthread_mutex_lock(&mutex);
	if(Qnode != NULL){
		if(De_Queue==NULL)
		{
			De_Queue = Qnode;
			if(De_Queue!=NULL)
			{
				De_Queue->next = NULL;
				//return 0;
			}
		}
		else
		{
			Qhead = De_Queue;
			while(Qhead->next != NULL){
					Qhead = Qhead->next;
			}
			if(Qhead->next == NULL){
				Qnode->next = NULL;
				Qhead->next = Qnode;
				//return 0;
			}
		}
	}

	if(Pnode != NULL)
	{
		if(Pa_Queue==NULL)
		{
			Pa_Queue = Pnode;
			if(Pa_Queue!=NULL)
			{
				Pa_Queue->next = NULL;
				//return 0;
			}
		}
		else
		{
			Phead = Pa_Queue;
			while(Phead->next != NULL){
					Phead = Phead->next;
			}
			if(Phead->next == NULL){
				Pnode->next = NULL;
				Phead->next = Pnode;
				//return 0;
			}
		}
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}


int sendtail()
{
	using namespace std;
	Ip_Queue *head=NULL;
	Pa_Node *headnode=NULL;
	timeval seconds;
	int i = 0;
	int nowseconds = 0;
	int flag = 0;	
	while(1)
	{
		printf("now send\n");
		if(m_hipq_1==NULL) 
		{
			printf("no ipq\n");
			sleep(1);
			continue;
		}
		if(IP_Queue == NULL) 
		{
			sleep(1);
			continue;
		}
		head = IP_Queue;
		if(head!=NULL)
		{
			head = IP_Queue;
			headnode = IP_Queue->pa_node;
					
			while(headnode!=NULL)    //Preocess pa_node queue which has same data
			{
				usleep(100);
				if(headnode->packet_content.id == 0) {
					head->pa_node=NULL;
					continue;
				}
				printf("send packet is %lu,%lu\n",headnode->packet_content.id,headnode->packet_content.data);

				gettimeofday(&end_time,0);
				printf("cost_time=%lf ms\n",(double)(1000000*(end_time.tv_sec - headnode->start_time.tv_sec) + end_time.tv_usec - headnode->start_time.tv_usec)/1000);

				total_send ++;
				
				printf("total_send = %ld\n", total_send);
				printf("total_recv = %ld\n", total_recv);

				ipq_set_verdict( m_hipq_1, headnode->packet_content.id, NF_ACCEPT,  0, NULL  );			
				gettimeofday(&seconds,0);
				for(i=0;i<MAX_NUM;i++)
				{
					if(WK_SET[i] == 0)   //record the first meet package
					{
						nowseconds = i;
						WK_TIME[i] = seconds;
						nowseconds = i;
						break;
					}
					if(WK_SET[i] == headnode->packet_content.data)   //if there is a replicated data, do not record that and break the loop
					{
						//nowseconds = -1;
						flag = 1;
						printf("found one in WKSET!!!!\n");
						WK_TIME[i] = seconds;
						break;
					}
					if(WK_TIME[i].tv_usec < WK_TIME[nowseconds].tv_usec)
						nowseconds = i;
				}
				if(!flag)    //replace the last one whose time earlier than current time.
				{
					printf("Join WKSET!!!!!!!!!!!!!!!!!1!!!!\n");
					WK_SET[nowseconds] = headnode->packet_content.data;
					WK_TIME[nowseconds] = seconds;
				}
				flag = 0;
				head->pa_node=headnode->next;

				if(headnode!=NULL)
						insertDequeue(NULL, headnode);
                headnode = head->pa_node;
			}
			queue_num --;
			printf("queue_num = %d\n", queue_num);
			IP_Queue = head->next;
			if(head!=NULL)
				insertDequeue(head, NULL);
		//		free(head);
		
		}
		usleep(100);
	}
	pthread_detach(pthread_self());
	return 1;
		
}



int deleteQueue()
{
	using namespace std;
	Ip_Queue *Qhead=NULL;
	Pa_Node *Phead=NULL;
	while(1){
		if(De_Queue == NULL && Pa_Queue == NULL) 
		{
			usleep(1000);
			continue;
		}
		//cout << "delete start" << endl;
		pthread_mutex_lock(&mutex);
		Qhead = De_Queue;
		if(Qhead != NULL)
		{
			De_Queue = Qhead->next;
			free(Qhead);
			cout << "delete Queue one" << endl;
		}

		Phead = Pa_Queue;
		if(Phead != NULL)
		{
			Pa_Queue = Phead->next;
			free(Phead);
			cout << "delete Pa one" << endl;
		}
		pthread_mutex_unlock(&mutex);
		usleep(1000);
	}
	pthread_detach(pthread_self());
	return 1;
}



bool IPQ::Perform1()
{
	while(1)
	{
		Perform();
	}
}

bool IPQ::SendPacket()
{
	pthread_t hThread;
    pthread_create(&hThread,NULL,(void*(*)(void*))sendtail,NULL);  
	return 1;
}

bool IPQ::DePacket()
{
	pthread_t hThread;
	pthread_mutex_init(&mutex,NULL);
	pthread_create(&hThread,NULL,(void*(*)(void*))deleteQueue,NULL);  
	return 1;
}

void IPQ::OnPacket( ipq_packet_msg_t* pp )
{
//		ShowPacketContent( pp );
		using namespace std;
		int sql_len;
		const IPHeader * pIP = (IPHeader*)((char*)pp + sizeof( ipq_packet_msg_t ) );
		const TCPHeader * pTCP = (TCPHeader*)((unsigned int*)pIP + pIP->IHL);
		const void * pData = (unsigned int*)pTCP + pTCP->DataOffset;
		size_t data_len = ntohs(pIP->TotalLen) - ( (char*)pData - (char*)pIP );
 		char _szBuf_s[INET_ADDRSTRLEN];
 		char _szBuf_d[INET_ADDRSTRLEN];
		int has_queue = 0;
		int i = 0;
		unsigned long data =0;
		if ( 0 == data_len )
		{
			AcceptPacket( pp );
			return;
		}
		data = pIP->DestAddr+pIP->SourceAddr;

		total_recv ++;
		printf("total_rev = %ld\n", total_recv);
		
		for(i=0;i<MAX_NUM;i++)                 //check if workingSet has records of same data with the new one
        {
        	//printf("WK_SET is %d\n",WK_SET[i]);
			//if( WK_SET[i] == 0)
			//	continue;
			if( data == WK_SET[i])        //if the record has that data, send this package, and record the new reaching time.
			{
				gettimeofday(&WK_TIME[i],0);
				has_queue = 1;
				printf("has one!!!!!!!!!!!!!!!\n");
				break;
			} 
        }
		if(has_queue)
		{
			gettimeofday(&end_time,0);
			printf("cost_time=%lf ms\n",(double)(1000000*(end_time.tv_sec - start_time.tv_sec) + end_time.tv_usec - start_time.tv_usec)/1000);

			total_send++;
			printf("total_send = %ld\n", total_send);

			AcceptPacket( pp );
		}
		else           //if there isn't a same data package, insert it into waiting queue.
		{
			if(!inserttail(m_pack_id,pIP->DestAddr+pIP->SourceAddr,(char*)inet_ntop( AF_INET, &(pIP->DestAddr),_szBuf_d, sizeof( _szBuf_d ) ), (char*)inet_ntop( AF_INET, &(pIP->SourceAddr),_szBuf_d, sizeof( _szBuf_d ) )))
			DropPacket();	
		}
		return;
}

	void IPQ::AcceptPacket( ipq_packet_msg_t* pp )
	{
                //Connections--;
                //printf("con = %d",Connections);
		if ( m_bisvalid )
		{
		    ipq_set_verdict( m_hipq, m_pack_id, NF_ACCEPT,  0, NULL  );
			_reset();
		}

		return;
	}


	void IPQ::DropPacket(void)
	{
               // Connections--;
		if ( m_bisvalid )
		{
			ipq_set_verdict( m_hipq, m_pack_id, NF_DROP,0,NULL );
			_reset();
		}

		return;
	}

	IPQ::~IPQ(void)
	{
		if ( NULL != m_hipq )
		{
			ipq_destroy_handle( m_hipq );
			m_hipq = NULL;
		}
		return;
	}
}; // namespace ipq

