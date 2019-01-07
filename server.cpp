#include <unistd.h>
#include <cstdio>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
#include <cstdio>
#include <fstream>
#include <cmath>
#define SERVER_PORT 8000
#define FD_SIZE 3
using namespace std;
bool isPrime(int num);
int exgcd(int a, unsigned long int b,unsigned long int &x,unsigned long int &y);
void producePKey();
unsigned long int PowerMod(unsigned long int a,unsigned long int  b,unsigned long int c); 
void splice(char str[20],int cnt,unsigned long int  &number);
void desDecry(char *key,char *input,char output[1024]);
void desEncry(char *key,char *input,char output[1024]);
int init(struct sockaddr_in addr);
void handle(int acceptRet);
void Link(int sockfd);

typedef struct{
	int id;
	unsigned long int key;
	int clientfd;
}Client;
Client client[2]; 
unsigned long int e,d,n;
int status=-1;
int ACC;
//fint client_sockfd[FD_SIZE];
unsigned long int secretKey1,secretKey2,decryKeyA,decryKeyB;
void * ForRead(void *arg);
int main(int argc,char *argv[])
{
	int sockfd;
	struct sockaddr_in serveraddr;
	producePKey();
	cout<<"e:"<<e<<" d: "<<d<<" n: "<<n<<endl;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_addr.s_addr=inet_addr("127.0.0.1");
	serveraddr.sin_port=htons(SERVER_PORT);
	sockfd=init(serveraddr);
	if(sockfd==-1)
	{
		printf("init error\n");
		return -1;
	}
	int opt=1;
    	setsockopt(sockfd , SOL_SOCKET , SO_REUSEADDR , &opt , sizeof(opt));
	printf("init success!\n");
	Link(sockfd);
	close(sockfd);
	return 0;
}


int init(struct sockaddr_in addr)
{
	int sockfd;
	int ret;//返回值，记录错误码
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	if(sockfd==-1)
		return -1;
	ret=bind(sockfd,(struct sockaddr*)&addr,sizeof(addr));
	if(ret==-1)
		return -1;
	listen(sockfd,10);
	return sockfd;
}
int idA,idB,N1;
void Link(int server_sockfd)
{
	
	//int Maxfd;
	int acceptRet;
	struct sockaddr_in acceptaddr;
	socklen_t len;//地址大小
	fd_set rset,allset;
	int maxfd=server_sockfd;
	char buffer[1024]="";
	char publicKey[1024]="";
	int value;
	snprintf(publicKey,sizeof(publicKey),"k%ld#%ld",e,n);
	cout<<"publicKey:"<<publicKey<<endl;
	int k,nready,maxi=-1;
	int socketfd;
	for(k=0;k<FD_SIZE;++k)
	{
		client[k].clientfd=-1;
		client[k].id=-1;
		client[k].key=-1;
	}
	FD_ZERO(&allset);
	FD_SET(server_sockfd,&allset);
	
	while(1)
	{
		rset=allset;
		nready=select(maxfd+1,&rset,NULL,NULL,0);
		if(FD_ISSET(server_sockfd,&rset))
		{
			len=sizeof(acceptaddr);
			acceptRet=accept(server_sockfd,(struct sockaddr*) &acceptaddr,&len);
	      		cout<<"acceptRet:"<<acceptRet<<endl;
			if(acceptRet==-1){
				perror("accept error");
				exit(1);
			}
			cout<<"received a connection from "<<inet_ntoa(acceptaddr.sin_addr)<<endl;
			send(acceptRet,publicKey,1024,0);
			//cout<<"value:"<<value<<endl;
			for(k=0;k<FD_SIZE;++k)
			{
				if(client[k].clientfd<0)
				{
					client[k].clientfd=acceptRet;
					break;
				}
			}
			if(k==FD_SIZE)
			{
				perror("too many connection");
				exit(1);
			}
			FD_SET(acceptRet,&allset);
			if(acceptRet>maxfd)
				maxfd=acceptRet;
			if(k>maxi)
				maxi=k;
			if(--nready<=0)
				continue;
				
		}
		//cout<<"maxi"<<maxi<<endl;
		for(k=0;k<2;++k)
		{
			if((socketfd=client[k].clientfd)<0)
				break;
			if(FD_ISSET(socketfd,&rset))
			{
				
				handle(socketfd);
				//FD_CLR(socketfd,&rset);
				continue;
				
			}
			
		}
		
	}
	return;	
}
char decryResA[1024]={0};
char decryResB[1024]={0};
void handle(int acceptRet)
{
		char recvbuffer[1024]="",recvbuf[1024]="",recbuffer[1024]="";
		char tempA[1024]="",tempB[1024]="",mytemp[1024]="";
		char *p=NULL,*pt=NULL,*pr=NULL;
		int recvRet,cnt,number[3],num;
		unsigned long int encryA[1024],encryB[1024];
		char Ks[1024]="network";
		int flag=0,idQ,idR;
		if((recvRet=recv(acceptRet,recvbuffer,1024,0))==0)
		{
		        cout<<acceptRet<<" exit"<<endl;
			close(acceptRet);
		}
		else
		{
			//cout<<"recvbuffer:"<<recvbuffer<<endl;
			stringstream temp1,temp2,m1,m2;
			string s1,s2;
			int tmpfd,tmpid;
			
			if(recvbuffer[0]=='A') //一类消息
			{
				if(recvbuffer[1]<'5')//两个客户端一个id小于5一个大于5,这样做是为了避免覆盖
				{
					strcpy(recvbuf,recvbuffer);
					tmpfd=acceptRet;
					for(int j=0;j<strlen(recvbuf)-3;j++)//加密过的客户端和服务器间密钥
					{
					
						tempA[j]=recvbuf[j+3];
						//cout<<"tempA:"<<tempA[j]<<" ";
						encryA[j]=tempA[j]-48;
						temp1<<encryA[j];
						s1=temp1.str();
					
					}
					//cout<<"s1:"<<s1<<endl;
					m1<<s1;
					m1>>secretKey1; //将加密过的密钥 由char数组一步步转换成unsigned long int
					//cout<<"secretKey1:"<<secretKey1<<endl;
					//cout<<"n:"<<endl;
					decryKeyA=PowerMod(secretKey1,36251,89951);//解密后的 客户端和服务器间密钥
					cout<<"decryKeyA:"<<decryKeyA<<endl;
					client[0].clientfd=tmpfd;   //将id、acceptfd、key和一个客户端想绑定
					client[0].id=int(recvbuf[1])-48;
					client[0].key=decryKeyA;
				}
				else if(recvbuffer[1]>'5')
				{
					for(int j=0;j<strlen(recvbuffer)-3;j++)//加密过的客户端和服务器间密钥
					{
					
						tempB[j]=recvbuffer[j+3];
						//cout<<"tempB:"<<tempB[j]<<" ";
						encryB[j]=tempB[j]-48;
						temp2<<encryB[j];
						s2=temp2.str();
					
					}
					//cout<<"s2:"<<s2<<endl;
					m2<<s2;
					m2>>secretKey2; //将加密过的密钥 由char数组一步步转换成unsigned long int
					//cout<<"secretKey2:"<<secretKey2<<endl;
					//cout<<"n:"<<endl;
					decryKeyB=PowerMod(secretKey2,36251,89951);//解密后的 客户端和服务器间密钥
					cout<<"decryKeyB:"<<decryKeyB<<endl;
					client[1].clientfd=acceptRet;
					client[1].id=int(recvbuffer[1])-48;
					client[1].key=decryKeyB;
				}
				flag++;
			
			for(int i=0;i<FD_SIZE-1;i++)
				cout<<"fd: "<<client[i].clientfd<<" id: "<<client[i].id<<" key: "<<client[i].key<<endl;
			}
			else if(recvbuffer[0]=='B') //二类消息
			{
				stringstream mystr1,mystr2,strA,strB,strRes;
				string res1,res2,smA,smB,smRes;
				
				//cout<<"length of output:"<<sizeof
				for(int j=0;j<strlen(recvbuffer)-1;j++)
					tempA[j]=recvbuffer[j+1];
				strcpy(mytemp,tempA);
				pr=strtok(tempA,"#"); 
				cnt=0;
				while(pr!=NULL)  //分割字符串 找出idA idB N1
				{
					num=atoi(pr);
					number[cnt]=num;
					pr=strtok(NULL,"#");
					cnt++;
				 }   
				idQ=number[0];
				idR=number[1];
				N1=number[2];
				cout<<"idQ:"<<idQ<<endl;
				cout<<"idR:"<<idR<<endl;
				cout<<"N1:"<<N1<<endl;
				
				if(idQ==client[0].id)  //client[0]是请求者，client[1]是被请求者
				{
					strA<<Ks;
					strA<<'#';
					for(int j=0;j<strlen(mytemp);j++)
					{
						strA<<mytemp[j];
						smA=strA.str();
					}		
					cout<<"smA:"<<smA<<endl;
					
					mystr1<<client[0].key;
					mystr1>>res1;  //把unsigned long int 转化成char数组
					cout<<"res1:"<<res1<<endl; //key
					desDecry((char *)res1.c_str(),(char *)smA.c_str(),decryResA);//调用DES 用密钥 k加密smA`
					cout<<"decryResA:"<<decryResA<<endl;					

					strB<<Ks;
					strB<<'#';
					strB<<idQ;
					strB>>smB;
					cout<<"smB:"<<smB<<endl;
					
					mystr2<<client[1].key;
					mystr2>>res2;  //把unsigned long int 转化成char数组
					cout<<"res2:"<<res2<<endl; //key
					desDecry((char *)res2.c_str(),(char *)smB.c_str(),decryResB);//调用DES 用密钥 k加密smB
					cout<<"decryResB:"<<decryResB<<endl;
					
					strRes<<'t'; //标记一下，方便客户端按信息类别处理
					strRes<<decryResA;
					strRes<<'#';
					strRes<<decryResB; //将它们拼起来发给A
					strRes>>smRes;				
					cout<<"smRes:"<<smRes<<endl;
					send(client[0].clientfd,smRes.c_str(),1024,0);
				}
				else if(idQ==client[1].id) //client[1]是请求者，client[0]是被请求者
				{
					strA<<Ks;
					strA<<'#';
					for(int j=0;j<strlen(mytemp);j++)
					{
						strA<<mytemp[j];
						smA=strA.str();
					}		
					cout<<"smA:"<<smA<<endl;
		
					mystr1<<client[1].key;
					mystr1>>res1;  //把unsigned long int 转化成char数组
					cout<<"res1:"<<res1<<endl; //key
					desDecry((char *)res1.c_str(),(char *)smA.c_str(),decryResA);//调用DES 用密钥 k加密smA
					cout<<"decryResA:"<<decryResA<<endl;					

					strB<<Ks;
					strB<<'#';
					strB<<idQ;
					strB>>smB;
					cout<<"smB:"<<smB<<endl;
					
					mystr2<<client[0].key;
					mystr2>>res2;  //把unsigned long int 转化成char数组
					cout<<"res2:"<<res2<<endl; //key
					desDecry((char *)res2.c_str(),(char *)smB.c_str(),decryResB);//调用DES 用密钥 k加密smB
					cout<<"decryResB:"<<decryResB<<endl;

					strRes<<'t'; //标记一下，方便客户端按信息类别处理
					strRes<<decryResA;
					strRes<<'#';
					strRes<<decryResB; //将它们拼起来发给A
					strRes>>smRes;				
					cout<<"smRes:"<<smRes<<endl;
					send(client[1].clientfd,smRes.c_str(),1024,0);

				}
				
			}
			else if(recvbuffer[0]=='C')	//三类消息
			{
				char zhuan[1024]={0};
				strcpy(zhuan,recvbuffer);
				if(acceptRet==client[0].clientfd)  //将消息转发给另一客户端
					send(client[1].clientfd,zhuan,1024,0);
				else
					send(client[0].clientfd,zhuan,1024,0);
			}
			else if(recvbuffer[0]=='D')  //四类消息
			{		
				
				char zhuan[1024]={0};
				strcpy(zhuan,recvbuffer);
				if(acceptRet==client[0].clientfd)  //将消息转发给另一客户端
				{
					send(client[1].clientfd,zhuan,1024,0);
					ACC=client[1].clientfd;
				}
				else
				{
					send(client[0].clientfd,zhuan,1024,0);
					ACC=client[0].clientfd;
				}
				status=1;
				
			}
			else if(recvbuffer[0]=='s'&&status==1)
			{
				//cout<<"status:"<<endl;
				send(ACC,"Start!",1024,0);
				status=-1;

			}
			else if(recvbuffer[0]=='E')  //五类消息
			{		
				char zhuan[1024]={0};
				strcpy(zhuan,recvbuffer);
				cout<<"E zhuan:"<<zhuan<<endl;
				cout<<"acceptRet:"<<acceptRet<<endl;
				cout<<"client[0].clientfd:"<<client[0].clientfd<<endl;
				cout<<"client[1].clientfd:"<<client[1].clientfd<<endl;
				if(acceptRet==client[0].clientfd)  //将消息转发给另一客户端
					send(client[1].clientfd,zhuan,1024,0);
				else
					send(client[0].clientfd,zhuan,1024,0);
			}			
		}
	return;
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
	//cout<<"output:"<<output<<endl;
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
	//cout<<"output:"<<output<<endl;
}
void producePKey()
{
	int prime[500]={0};
	bool ret;
	srand(time(NULL));
	int flag=1;

	int i=0,num,index=0;
	//int message=2127;
	//int secretMess;
	unsigned long int p,q,T,y;
	fstream file;
	file.open("prime.txt",ios::out);
	if(!file)
		cout<<"error open"<<endl;
	for(int k=2;k<500;k++)
	{
		ret=isPrime(k);
		if(ret)
		{
			file<<k<<" ";
			prime[index]=k;
			index++;
		}
	}

	for(int k=0;k<=index;k++)
	{
		if(prime[k]>300)
		{
			p=prime[k-1];
			q=prime[k];
			break;
		}
	}
	n=p*q;
	cout<<"n:"<<n<<endl;
	T=(p-1)*(q-1);
	for(int j=0;j<T;j+=1331)  
	{
		int gcd=exgcd(j,T,d,y);
		if(gcd==1&&d>0)
		{
			e=j;
			break;
		}
	}
}


bool isPrime(int num)
{
	int tmp=sqrt(num);
	for(int i=2;i<=tmp;i++)
	{
	    if(num==0||num==1||num%i==0)
		return false;
	}

	return true;
}

//gcd(e,T)=1
//d*e=1 mod T
int exgcd(int a, unsigned long int b,unsigned long int &x,unsigned long int &y)
{
    if (b == 0){
        x = 1;
        y = 0;
        return a;
    }
    unsigned long int x1,y1;
    int ans = exgcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - a / b * y1;
    return ans;//ans最大公约数
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
void splice(char str[20],int cnt,unsigned long int  &number)//cnt表示参数个数
{
	int num[20];
	string s;
	stringstream temp,m;
	for(int i=0;i<strlen(str);i++)
	{
		num[i]=str[i]; //将字符转换成其对应的ascii码值
		temp<<num[i];
		s=temp.str();
		//cout<<num[i]<<" "; 
	}
	if(cnt==4)
	{
		int arr[3];
		arr[0]=idA;
		arr[1]=idB;
		arr[2]=N1;//分别为IDA IDB N1
		for(int i=0;i<3;i++)
		{
			temp<<arr[i];
			s=temp.str();
		}
		m<<s;
		m>>number;
		cout<<"number:"<<number<<endl; //拼接后的unsigned long int 类型的数字
	}
	else if(cnt==2)
	{
		temp<<idA;
		s=temp.str();
		m<<s;
		m>>number;
		cout<<"number:"<<number<<endl; //拼接后的unsigned long int 类型的数字
	}
	
 } 
/*
send成功并返回多少字节，就像货站装完车已经在自己的网站上写到你的货已经派送，派送了什么货。
至于车什么时候出发，什么时候到达目的地，货站控制不了。
*/
