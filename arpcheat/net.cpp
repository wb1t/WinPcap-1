#include"pcap.h"
int main(){
	pcap_if_t *all_devs;
	
	char errBuf[PCAP_ERRBUF_SIZE];
	//get local device list
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&all_devs,errBuf)==-1){
		fprintf(stderr,"ERROR:%s\n",errBuf);
		exit(1);
	}

	//print list
	int count=1;
	for(pcap_if_t *d=all_devs;d!=NULL;d=d->next){
		printf("%d %s\n",count++,d->name);
		printf("addr:%d\n,descp:%s\n",d->addresses,d->description);
	}
	if(count==1){
		printf("No interface found!make sure WinPcap is stalled.\n");
	}
}