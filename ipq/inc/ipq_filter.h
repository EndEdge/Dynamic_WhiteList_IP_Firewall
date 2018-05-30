
#ifndef __IPQ_FILTER_H__
#define __IPQ_FILTER_H__

#include "ipq_wrapper.h"
#include <map>
#include <boost/regex.hpp>
int sendtail();
namespace ipq
{
	class RegxSet
	{
	private:
		std::map<std::string, boost::regex> m_map;
	public:
		RegxSet(void);
		bool AddRegxString( const std::string& strReg );
		bool RemoveRegxString( const std::string& strReg );
		// If the _s matches any regx in m_map, return true. strReg will contain the regx string.
		bool Match( const std::string& _s, std::string& strReg );
		virtual ~RegxSet(void);
	}; // class RegxSet

	class IPQEx: public IPQ, public RegxSet
	{
	public:
		IPQEx(void);
		// return true if the packet should be accepted, false for dropped.
		virtual bool OnFilterContent( const std::string& strSourceIP,\
									  const unsigned short SourcePort, \
									  const std::string& strDestIP, \
									  const unsigned short DestPort, \
									  const void * pdata, \
									  const size_t data_len );
		virtual ~IPQEx(void);
	}; // class IPQEx;
}; // namespace ipq
#endif // __IPQ_FILTER_H__

