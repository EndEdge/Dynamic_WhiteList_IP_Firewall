
#include <iostream>
#include "ipq_filter.h"
#include <pthread.h>

int main( int argc, char * argv[] )
{
	using namespace std;
	bool bRtn = false;
	ipq::IPQEx _ipq;
	pthread_t hThread;
	int hThreadId;
     
    char tmp[255];
    int i = 0;
	_ipq.m_dbver = 1;
	printf("program start\n");\
	cout << "aaaaaa" << endl;
	_ipq.SendPacket();
	_ipq.DePacket();

	pthread_create(&hThread,NULL,(void*(*)(void*))_ipq.Perform1(),NULL);


	while( true )
	{
		sleep(100000000);
	} // while
	return 0;

}
