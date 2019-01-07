#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
using namespace std;

unsigned long int PowerMod(unsigned long int a,unsigned long int  b,unsigned long int c);
int init(struct sockaddr_in addr);
void desDecry(char *key,char *input,char output[1024]);
void desEncry(char *key,char *input,char output[1024]);
//void * ForRead(void *arg);
void *ForWrite(void *arg);

char publicKey[1024]="";
char recvbuffer[1024]="";
char sendbuffer[1024]="";
unsigned long int e=0,n=0;
unsigned long int secretKey,key;
string s;
int status=-1;

int main(int argc,char *argv[])
{
	pthread_t rid,wid;
	int sockfd;
	struct sockaddr_in client_addr;
	client_addr.sin_family=AF_INET;
	client_addr.sin_port=htons(8000);
	inet_pton(AF_INET,"127.0.0.1",&client_addr.sin_addr);//函数名中的p和n非别代表表达（presentation）和数值（numeric）
	sockfd=init(client_addr);
	pthread_create(&wid,0,ForWrite,&sockfd);
	pthread_join(wid,0);
	
	
	//producePKey(e,d,n);
	
	close(sockfd);
	return 0;	
}

int init(struct sockaddr_in addr)
{
	int sockfd;
	int ret;
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	ret=connect(sockfd,(struct sockaddr*)&addr,sizeof(addr));
	return sockfd;
}
void * ForRead(void *arg)//void*可以传入任意类型的指针,返回值也可以是任意类型的指针
{
	char talk[20];
	int *sockfd=(int *)arg;
	while(1)
	{
		memset(talk,0,20);
		fgets(talk,20,stdin);
		send(*sockfd,talk,strlen(talk)+1,0);
	}
}

void *ForWrite(void *arg)
{
	int *sockfd=(int *)arg;
	unsigned long int number[2],num;
	char *p=NULL,*pt=NULL;
	int ret,m,cnt;
	stringstream st,stemp,stm;
	string stp,sp;
	char ch,opt;
	char decryRes[1024]="";
	char recvTemp[1024]="",handlebuffer[1024]="",recbuffer[1024]="",senbuffer[1024]="";
	int idA=1,idB=2,N1=8,N2=9;
	int id,id1,id2;
	char yanz[1024]="",Ks[1024]="";
	while(1)
	{
		memset(recvbuffer,0,1024);
		recv(*sockfd,recvbuffer,1024,0);
		//cout<<"talkWrite[0]"<<talkWrite[0]<<endl;
		if(recvbuffer[0]=='k')//收到服务器的公钥  （收到信息的第一个字母为K 表示发的是服务器公钥）
		{
			for(int i=0;i<strlen(recvbuffer)-1;i++)
				publicKey[i]=recvbuffer[i+1];
			cout<<"recv:"<<publicKey<<endl;			
			p=strtok(publicKey,"#");
			m=0;
			while(p!=NULL)
			{
				num=atoi(p);
				number[m]=num;
				p=strtok(NULL,"#");
				m++;
			 }   
			e=number[0]; //服务器的公钥
			n=number[1];
			cout<<"e:"<<e<<endl;
			cout<<"n:"<<n<<endl;
			cin>>key; //服务器和客户端之间的密钥
			
			secretKey=PowerMod(key,e,n); //用服务器的公钥把 客户端和服务器的密钥进行加密
			st<<'A'; //标识是一类消息
			cin>>id; //输入一个字母区别客户端A B 
			st<<id;
			st<<'#';
			st<<secretKey;
			s=st.str();
			strcpy(sendbuffer,s.c_str());
			cout<<"send:"<<sendbuffer<<endl;
			send(*sockfd,sendbuffer,1024,0);//将服务器和客户端间密钥发给服务器
	  
			cin>>opt;
			if(opt=='Y')
			{				
				stemp<<'B';// B表示这条消息发送的是idA  idB  N1,二类消息
				cin>>id1;
				stemp<<id1;	//表示发起请求消息的是A还是B
				stemp<<'#';  //'#'作为分隔符
				cin>>id2;   //被请求会话的对象
				stemp<<id2;
				stemp<<'#';
				stemp<<N1;
				stp=stemp.str();
				strcpy(yanz,stp.c_str());
				cout<<"send:"<<stp<<endl;
				send(*sockfd,yanz,1024,0);
			}
			else
				continue;
		}
		//recv(*sockfd,recvbuffer,1024,0);
		else if(recvbuffer[0]=='t')
		{
			stringstream mess,mystr1,mystr2;
			string res1,res2,sendMess,smA;
			char encryResA[1024]={0};
			char encryResB[1024]={0};
			int g=0;
			char *px;
			mystr1<<key;
			mystr1>>res1;  //把unsigned long int 转化成char数组
			cout<<"res1:"<<res1<<endl; //key
								
			for(int j=0;j<strlen(recvbuffer);j++)
				recvTemp[j]=recvbuffer[j+1];  //略过开头的t
			pt=strtok(recvTemp,"#");
			cnt=0;
			status=1;
			while(pt!=NULL)
			{
				cnt++;
				if(cnt%2!=0) //取出recvTemp +号前面的部分 即ks || IDA ||IDB ||N1
				{
					strcpy(handlebuffer,pt);  //!!!!
					cout<<"recvebuffer:"<<handlebuffer<<endl;
					desEncry((char *)res1.c_str(),(char *)handlebuffer,encryResA);
					cout<<"encryResA:"<<encryResA<<endl;
					
					px=strtok(encryResA,"#");
					g=0;
					while(px!=NULL)
					{
						if(g%2==0&&g==0)
							strcpy(Ks,px);

						px=strtok(NULL,"#");
						g++;
					 }   
					cout<<"Ks:"<<Ks<<endl;
					//解密结果为decryRes
					
				}
				pt=strtok(NULL,"#");
			} 
			int lengt;  
			lengt=strlen(handlebuffer);
			for(int  k=lengt+1;k<strlen(recvbuffer);k++)
				senbuffer[k-lengt-1]=recvbuffer[k+1];
			stm<<'C';
			stm<<senbuffer;
			cout<<"sendbuffer:"<<senbuffer<<endl;
			sp=stm.str();
			send(*sockfd,sp.c_str(),1024,0); //将 ks||idA 发给另一客户
		}
		else if(recvbuffer[0]=='C')
		{
			char buf[1024]="";
			char bufRes[1024]="";
			char mesEncry[1024]="";
			stringstream mess,mystr1,mystr2;
			string res1,res2,sendMess,smA;
			char encryResA[1024]={0};
			char encryResB[1024]={0};
			char *px=NULL;
			int g;
			
			for(int j=0;j<strlen(recvbuffer)-1;j++)
				buf[j]=recvbuffer[j+1]; //略过C
		//	cout<<"buf"<<endl;
			
			mystr1<<key;
			mystr1>>res1;  //把unsigned long int 转化成char数组
			cout<<"res1:"<<res1<<endl; //key
			desEncry((char *)res1.c_str(),buf,encryResA);//调用DES 用密钥 k解密
			cout<<"encryResA:"<<encryResA<<endl;	
		
			px=strtok(encryResA,"#");
			g=0;
			while(px!=NULL)
			{
			    if(g%2==0&&g==0)
				strcpy(Ks,px);
			    px=strtok(NULL,"#");
			    g++;
			 }   
			cout<<"Ks:"<<Ks<<endl;//解密结果 encryResA  获取ks
			//des(key,buf,bufRes);  
			
			char message[1024]="9";
			desDecry(Ks,message,encryResB);	//用ks加密message，加密结果是mesEncry  发给另一客户端
			cout<<"encryResB:"<<encryResB<<endl;
			mess<<'D';
			mess<<encryResB;
			sendMess=mess.str();
			cout<<"sendMess:"<<sendMess<<endl;
			send(*sockfd,sendMess.c_str(),1024,0);

		}
		else if(recvbuffer[0]=='D')
		{
			char getMess[1024]="";
			char *sendMess=(char *)malloc(1024);
			char encryMess[1024]="";
			char decryMess[1024]="";
			char sbf[1024]="start";
			stringstream stg;
			string ss;
			status=1;
			for(int j=0;j<strlen(recvbuffer)-1;j++)
				getMess[j]=recvbuffer[j+1]; //略过D
			cout<<"D getMess:"<<getMess<<endl;
			desEncry(Ks,getMess,encryMess);//用ks解密，获取解密结果encryMess
			cout<<"D encryMessage:"<<encryMess<<endl;
			
			send(*sockfd,sbf,1024,0);
		}
		else if(recvbuffer[0]=='S'&&status==1)
		{
			char *sendMess=(char *)malloc(1024);
			char encryMess[1024]="";
			char decryMess[1024]="";
			stringstream str1;
			string ss;
			char order;
			cin>>order;
			if(order=='F')
			{
				str1<<'E';
				cin>>sendMess;
				desDecry(Ks,sendMess,decryMess);
				cout<<"decryMess:"<<decryMess<<endl;
				str1<<decryMess;
				ss=str1.str();
				cout<<"ss:"<<ss<<endl;
				send(*sockfd,ss.c_str(),1024,0);
			}
			else if(order=='S')
				continue;

		}
		else if(status==1&&recvbuffer[0]=='E')
		{
			cout<<"E:"<<endl;
			char getMess[1024]="";
			char encryMess[1024]="";
			stringstream stg;
			string ss;
			for(int j=0;j<strlen(recvbuffer)-1;j++)
				getMess[j]=recvbuffer[j+1]; //略过E
			cout<<"E getMess:"<<getMess<<endl;
			desEncry(Ks,getMess,encryMess);//用ks解密，获取解密结果encryMess
			cout<<"E encryMessage:"<<encryMess<<endl;
		}

	}

}
void desDecry(char *key,char *input,char output[1024])
{
	char *command=(char *)malloc(1024*sizeof(char));
	char output1[1024]={0};
	memset(command,'\0',strlen(command));
	strcpy(command,"./desDecry ");
	strcat(command,key);  //res表示key
	strcat(command," ");
	strcat(command,input);  //要执行的命令
	cout<<"command:"<<command<<endl;
	FILE *fp;
	fp=popen(command,"r");
	fgets(output1,sizeof(output1),fp);
	strcpy(output,output1);
}

void desEncry(char *key,char *input,char output[1024])
{
	char *command=(char *)malloc(1024*sizeof(char));
	char output1[1024]={0};
	memset(command,'\0',strlen(command));
	strcpy(command,"./desEncry ");
	strcat(command,key);  //res表示key
	strcat(command," ");
	strcat(command,input);  //要执行的命令
	cout<<"command:"<<command<<endl;
	FILE *fp;
	fp=popen(command,"r");
	fgets(output1,sizeof(output1),fp);
	strcpy(output,output1);
}
unsigned long int PowerMod(unsigned long int a,unsigned long int  b,unsigned long int c)
{

	cout<<a<<"^"<<b<<"mod("<<c<<")=";
	unsigned long int ans=1;
	a=a%c;
	while(b!=0)
	{
		if(b&1) ans=(ans*a)%c;
		b>>=1;
		a=(a*a)%c;
	}
	
	cout<<ans<<endl;
	return ans;// ans是大数的次幂取模的结果

}
