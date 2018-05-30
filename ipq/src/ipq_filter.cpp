
#include "ipq_filter.h"
#include <iostream>
#include <stdio.h>

#define MAX_IPPACKET_SIZE	65535
namespace ipq
{
	RegxSet::RegxSet(void)
	{}
	
	bool RegxSet::AddRegxString( const std::string& strReg )
	{
		using namespace std;

		if ( strReg.empty() )
		{
			return false;
		}
		if ( m_map.end() == m_map.find( strReg ) )
		{
			m_map[strReg] = boost::regex( strReg );
			return true;
		}
		else
		{
			return true;
		}
	}

	bool RegxSet::RemoveRegxString( const std::string& strReg )
	{
		using namespace std;

		map<string,boost::regex>::iterator _it = m_map.find( strReg );
		if ( m_map.end() == _it )
		{
			return false;
		}
		else
		{
			m_map.erase( _it );
			return true;
		}
	}
	
	// If the _s matches any regx in m_map, return true. strReg will contain the regx string.
	bool RegxSet::Match( const std::string& _s, std::string& strReg )
	{
		using namespace std;
		for ( map<string,boost::regex>::const_iterator _cp = m_map.begin(); \
				m_map.end() != _cp; ++_cp )
		{
			if ( boost::regex_match( _s, _cp->second ) )
			{
				strReg = _cp->first;
				return true;
			}
		}
		return false;
	}

	RegxSet::~RegxSet(void)
	{
		return;
	}

	IPQEx::IPQEx(void):
	IPQ( 0, AF_INET, IPQ_COPY_PACKET, MAX_IPPACKET_SIZE)
	{
		return;
	}
	
	//return true if the packet should be accepted, false for dropped.
	bool IPQEx::OnFilterContent( const std::string& strSourceIP,\
								 const unsigned short SourcePort, \
								 const std::string& strDestIP, \
								 const unsigned short DestPort, \
								 const void * pdata, \
								 const size_t data_len )
	{
		using namespace std;
		string strRegx;
  
		if ( Match( string((char*)pdata, data_len),strRegx ) )
		{
			cout << strSourceIP << ":" << SourcePort << "->";
			cout << strDestIP << ":" << DestPort << endl;
			cout << "=Packet Blocked= \"" << strRegx << "\"" << endl;
      		
			return true;
		}
		else
   		{
   			FILE *fp;
      		time_t ltime;
      		char tempchar[260];
      		struct tm *p;
      		fp = fopen("/usr/local/tnswall/tnswall.log","a+");	
      		if(fp == NULL)
				return false;
      		time(&ltime);
      		p = localtime(&ltime);
			fprintf(fp,"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
      		fprintf(fp,"%s;%d;",strSourceIP.c_str(),SourcePort);
      		fprintf(fp,"%s;%d;",strDestIP.c_str(),DestPort);
			fprintf(fp,"%s",(char*)pdata);
      		fprintf(fp,"(");
      		fprintf(fp,"%d-",(1900+p->tm_year));
      		if((1+p->tm_mon)<10) fprintf(fp,"%d",0);
      			fprintf(fp,"%d-",(1+p->tm_mon));
      		if(p->tm_mday<10) fprintf(fp,"%d",0);
      			fprintf(fp,"%d ",p->tm_mday);
      		if(p->tm_hour<10) fprintf(fp,"%d",0);
      			fprintf(fp,"%d:",p->tm_hour);
      		if(p->tm_min<10) fprintf(fp,"%d",0);
      			fprintf(fp,"%d:",p->tm_min);
      		if(p->tm_sec<10) fprintf(fp,"%d",0);
      			fprintf(fp,"%d)\n",p->tm_sec);

			fclose(fp);
			
			return false;
		}
	}

	IPQEx::~IPQEx(void)
	{
		return;
	}
}; // namespace ipq

