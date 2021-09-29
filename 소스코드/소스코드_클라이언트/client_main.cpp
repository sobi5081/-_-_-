#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <WinSock2.h>
#include <thread>
#include <openssl/applink.c>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <conio.h>
#include "authclient.h"
#include "openssl_fn.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcryptoMD.lib")
#pragma comment(lib, "libsslMD.lib")

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define TIMESKEW 2
#define RSA_ALGORITHM_H

using namespace std;

void main_menu(AuthClient& client);
void write(AuthClient& client, int n_1);
void Priv_diary(AuthClient& client);
void shared_diary(AuthClient& client);
void aloneReadMenue(AuthClient& client);
void sharedReadMenue(AuthClient& client);
void init(AuthClient& client);
void process_msg(SOCK_MSG& message, AuthClient& client);
char* msg_encrypt(AuthClient& client, const char* contents, int& len, char* key);
char* msg_decrypt(AuthClient& client, const char* contents, int len, char* key);


/*�����Լ�. Ŭ���̾�Ʈ ��ü ���� �� ������ ���� �� �޽��� ���� ���.
*parameter: ����
*return: ���� �ڵ�
*/
int main()
{
	AuthClient client("127.0.0.1", 50000);
	client.recv_msg(process_msg);

	return 0;
}


/*
*�α��� ������ ���θ޴��� ���. �ش� �޴� ��ȣ �Է� �� �ش� ������� �б�.
*parameter: Ŭ���̾�Ʈ ��ü
*return: ����
*/
void main_menu(AuthClient& client)
{
	printf("\n-----------------------\n");
	printf("< ���� �޴� >\n");
	printf("-----------------------\n");
	printf("1. ���� ���̾\n");
	printf("2. ���� ���̾\n");
	printf("3. �α׾ƿ�\n");
	printf("-----------------------\n");
	int cmd;
	printf(">> ");
	scanf("%d", &cmd);
	switch (cmd) {
	case 1:
		client.send_msg("diaryPriv", 1, "1");
		return;

	case 2:
		client.send_msg("diaryShared", 1, "1");
		return;

	case 3:
		strcpy(client.sym_key, "0");
		client.send_msg("logout", 1, "1");
		return;
	}
}


/*
*���δ��̾ ���ٽ� ���δ��̾ �޴��� ���. �ش� �޴� ��ȣ �Է� �� �ش� ������� �б�.
*parameter: Ŭ���̾�Ʈ ��ü
*return: ����
*/
void Priv_diary(AuthClient& client)
{
	printf("\n-----------------------\n");
	printf("< ���� ���̾ >\n");
	printf("-----------------------\n");
	printf("1. ����\n");
	printf("2. ���\n");
	printf("3. �ڷΰ���\n");
	printf("-----------------------\n");
	int n;
	printf(">> ");
	scanf("%d", &n);
	switch (n) {
	case 1:
		write(client, 1);
		break;


	case 2:
		//��� - ȥ�� �� �ϱ� ��� �ޱ� ���� ���� ����
		printf("\n-----------------------\n");
		printf("���� ���̾ ���\n");
		printf("-----------------------\n");
		client.send_msg("readAL", 1, "0");	//readAL: read alone list
		break;

	case 3:
		client.send_msg("back2main", 1, "0");
		return;

	}
}


/*�������̾ ���ٽ� �������̾ �޴��� ���. �ش� �޴� ��ȣ �Է� �� �ش� ������� �б�.
*parameter: Ŭ���̾�Ʈ ��ü
*return: ����
*/
void shared_diary(AuthClient& client) {
	printf("\n-----------------------\n");
	printf("< ���� ���̾ >\n");
	printf("-----------------------\n");
	printf("1. ����\n");
	printf("2. ���\n");
	printf("3. �ڷΰ���\n");
	printf("-----------------------\n");

	int cmd;
	printf(">> ");
	scanf("%d", &cmd);
	switch (cmd) {
	case 1:
		//���� - ���� ����
		write(client, 2);
		break;

	case 2:
		//��� - ���� �� �ϱ� ��� �޾ƿ������� ���� ����
		client.send_msg("readShareList", 1, "0");   //readSL : read share list
		break;

	case 3:
		client.send_msg("back2main", 1, "0");
		return;
	}
}


/*���� ���� ȭ�� ���. �ش� �޴� ��ȣ �Է� �� �ش� ������� �б�.
*parameter: Ŭ���̾�Ʈ ��ü
*return: ����
*/
void init(AuthClient& client)
{

	int base_64_len;

	int cmd;
	char tmp_buf[32];
	int public_len;
	char public_len_buf[32];
	char id[32];
	char pw[32];
	unsigned char hash_pw[41];
	int random;
	printf("\n-----------------------\n");
	printf("1.�α���\n");
	printf("2.ȸ������\n");
	printf("3.����\n");
	printf("-----------------------\n");
	printf(">> ");
	scanf("%d", &cmd);
	std::string buf = "";

	char encrypt_buf[1024];
	char mdString[SHA_DIGEST_LENGTH * 2 + 1];

	switch (cmd)
	{
	case 1:	//�α���

		printf("\n���̵� �Է��ϼ��� : ");
		scanf("%s", id);




		//hasing((char*)pw, (char*)hash_pw, 100);

		//client.send_msg("loginID", 2, id,"filling");
		client.send_msg("loginID", 1, id);
		break;

	case 2: //ȸ������
		printf("���̵� �Է��ϼ��� : ");
		scanf("%s", id);
		printf("��й�ȣ�� �Է��ϼ��� : ");
		scanf("%s", pw);



		//�Է¹��� �н����� 100�� �ؽ�
		hasing((char*)pw, (char*)hash_pw, 100);
		//id, �̸�, �ؽ�100�� �� ��й�ȣ, ��ȣȭ�� ��ĪŰ ����  //��ĪŰ �Ⱥ���
		client.send_msg("join", 2, id, hash_pw);


		break;

	case 3:	//exit(0);
		exit(0);
	}
}


/*�ۼ��� ���̾ ������ �������� ��ĪŰ�� ��ȣȭ�� ��, Base64���ڵ�.
*parameter: Ŭ���̾�Ʈ ��ü, ��ȣȭ�� ����, ��ȣ���� ����, �������� ��ĪŰ
*return: base64 ���ڵ� �� ���ڿ�
*/
char* msg_encrypt(AuthClient& client, const char* contents, int& len, char* key) //��ȣ���� ���̵� �˾Ƶ־� ��
{
	//printf("��ȣȭ! ������� ��ĪŰ : %s\n", key);
	int lena;
	unsigned char buf[2048];
	memset(buf, 0, 2048);
	lena = client.encrypt_block(buf, (unsigned char*)contents, strlen((char*)contents), (unsigned char*)key);
	buf[lena] = 0;

	len = lena;

	return base64((unsigned char*)buf, 2048, lena);
}


/*�����κ��� ���� base64 ���ڵ� �� ���̾ ������ ���ڵ� �� ��, �������� ��ĪŰ�� ��ȣȭ.
*parameter: Ŭ���̾�Ʈ ��ü, base64�� ����
*return: ��ȣȭ�� ���ڿ�
*/
char* msg_decrypt(AuthClient& client, const char* contents, int len, char* key) //��ȣȭ �� ���� �־���� ��
{
	//printf("��ȣȭ! ������� ��ĪŰ : %s\n", key);
	int lena;
	char buf[2048];
	unsigned char buf2[2048];
	//printf("BASE64 :: %s\n", decode64((unsigned char*)contents, 2048));
	memcpy(buf, decode64((unsigned char*)contents, 2048), len); //�޸�ī��
	
	lena = client.decrypt_block(buf2, (unsigned char*)buf, len, (unsigned char*)key);
	buf2[lena] = 0;
	return (char*)buf2;

}


/*
*���̾ �ۼ� ��, ��ȣȭ�� base64 ���ڵ� �� ��, ������ ����.
*parameter: Ŭ���̾�Ʈ ��ü, ����/���� ���̾ ���а�
*return: ����
*/
void write(AuthClient& client, int n) {

	int cmd = n;
	wchar_t ch;
	wchar_t buf[4096];

	static char partner[64];

	int size = 0;;
	wchar_t* p = buf;
	wcscpy(buf, L"");
	switch (cmd)
	{
	case 1:	//���� ���̾ ����
	{
		printf("������ �Է��ϼ���. �ۼ��� ������ [Ctrl+Q]�� �����ּ���. \n");
		while (1)
		{
			ch = _getwche();

			if (ch == (char)13)
			{
				*(p++) = '\n';
				printf("\n");
			}
			else
			{
				*(p++) = ch;
			}
			if (ch == 17) break;
		}
		*(--p) = 0;
		wprintf(L"\n���� : \n%ls\n", buf);
		//ConvertWCtoC(buf);
		int len; //��ȣ���� ���� ���� ���� ������ְ�
		char tmp_buf[3000]; // ��ȣ�� ���� ��
		char tmp_buf2[32]; //��ȣ�� ���� ���� ��

		strcpy(tmp_buf, msg_encrypt(client, ConvertWCtoC(buf), len, client.sym_key)); //��ȣȭ�ؼ� tmp_buf�� ����
		sprintf(tmp_buf2, "%d", len); //��ȣ���� ���̸� tmp_buf2�� �־���
		client.send_msg("writePriv", 3, "1", tmp_buf, tmp_buf2);
		//3:�Ű�����3��, 1 : ���� ���̾, ������ �ΰ��� ��ȣ��, ��ȣ���� ���� --> �̷��� ������ ��

		break;
	}
	case 2:	//���� ���̾ ���� - ���� ���̵� üũ
	{
		printf("������ ���� ���̵� �Է��Ͻÿ� : \n");
		scanf("%s", partner);
		client.send_msg("writeSha_chk", 1, partner);

		break;
	}
	case 3:	//���� ���̾ ���� - ���� ���̵� ������ �� �ۼ�
	{
		printf("������ �Է��ϼ���. �ۼ��� ������ [Ctrl+Q]�� �����ּ���. \n");
		while (1)
		{
			ch = _getwche();

			if (ch == (char)13)
			{
				*(p++) = '\n';
				printf("\n");
			}
			else
			{
				*(p++) = ch;
			}
			if (ch == 17) break;
		}
		*(--p) = 0;
		wprintf(L"\n���� : \n%ls\n", buf);
		//ConvertWCtoC(buf);
		int len; //��ȣ���� ���� ���� ���� ������ְ�
		char tmp_buf[3000]; // ��ȣ�� ���� ��
		char tmp_buf2[32]; //��ȣ�� ���� ���� ��

		strcpy(tmp_buf, msg_encrypt(client, ConvertWCtoC(buf), len, client.sym_key)); //��ȣȭ�ؼ� tmp_buf�� ����
		sprintf(tmp_buf2, "%d", len); //��ȣ���� ���̸� tmp_buf2�� �־���
		client.send_msg("writeShared", 3, partner, tmp_buf, tmp_buf2);
		//3:�Ű�����3��, 1 : ���� ���̾, ������ �ΰ��� ��ȣ��, ��ȣ���� ���� --> �̷��� ������ ��

		break;
	}
	default:
		break;
	}


}


/*����ü�� ��ȯ�� �޽����� ������ ������ ����� �ش��ϴ� ������� �б�.
*parameter: ���� ����ü, Ŭ���̾�Ʈ ��ü
*return: ����
*/
void process_msg(SOCK_MSG& message, AuthClient& client)
{
	if (strcmp(message.header, "success") == 0) //���� - Ŭ���̾�Ʈ ���� ����
	{
		init(client);
	}
	else if (strcmp(message.header, "loginN") == 0) {	//�α���1
		/* �����κ��� N�� �޾ƿ�
		1. ����Ű ���� -> ������ ����Ű�� ��ȣȭ
		2. n-1�� �ؽ�
		3. ��ȣȭ ����, n-1�� �ؽ��� ��, ��ȣ��(����Ű) ����
		*/
														
		//������ ã�Ƽ� N�� ����
		int n = atoi(message.contents);
		//printf("n : %d\n", n);//�ӽ� ���

		int random=0;
		char sym_key[32];
		
		int public_len;
		char encrypt_buf[2048];
		char encrypt_buf_len[32];
		int base_64_len;
		srand(time(NULL));
		while (random < 1000) {
			random = rand() % 5000; //��ĪŰ�� �� ���� ����
		}
		
		//printf("��ĪŰ�� : %d\n", random);
		sprintf(sym_key, "%d", random);
	

		strcpy(client.sym_key, sym_key);

		public_len = publicEncrypt((char*)sym_key, encrypt_buf);

		sprintf(encrypt_buf_len, "%d", public_len);

		char pw[32];
		printf("��й�ȣ�� �Է��ϼ��� : ");
		scanf("%s", pw);
		//n-1 �ؽ��� ���� ����
		char hash_pw[SHA_DIGEST_LENGTH * 2 + 1];	//��й�ȣ �ؽ� ���� ����
		hasing((char*)pw, (char*)hash_pw, n - 1);	//n-1�� �ؽ�
		client.send_msg("login", 3, (const char*)hash_pw, encrypt_buf_len, base64((unsigned char*)encrypt_buf, 2048, base_64_len));
	}

	else if (strcmp(message.header, "login") == 0)	//�α���2
	{
		if (strcmp(message.contents, "1") == 0)	//�α��� ����
		{
			printf("\n* �α��� ����! *\n");
			main_menu(client);	//�α��� �� ���¿��� ���̴� �޴�
		}
		else if (strcmp(message.contents, "0") == 0)	//���̵� Ʋ�� ���
		{
			printf("\n* �ش� ����ڸ� ã�� �� �����ϴ� *\n");
			init(client);
		}
		else if (strcmp(message.contents, "2") == 0)	//��й�ȣ�� Ʋ�� ���
		{
			printf("\n* ��й�ȣ�� Ʋ�Ƚ��ϴ� *\n");
			init(client);
		}
	}

	else if (strcmp(message.header, "joinEnd") == 0) {	//ȸ������ �Ϸ�
		printf("\n* ȸ�������� �Ϸ�Ǿ����ϴ� *\n");
		init(client);
	}

	else if (strcmp(message.header, "diaryPriv") == 0) //���δ��̾ �޴� �Լ��� �б�
	{
		Priv_diary(client);
	}
	else if (strcmp(message.header, "writePrivEnd") == 0) {	//���� ���̾ �ۼ� �Ϸ�
		printf("\n\n* ���̾ �ۼ��� �Ϸ�Ǿ����ϴ� *\n");
		Priv_diary(client);
	}
	else if (strcmp(message.header, "writeSha_chk_rt") == 0) {	//���̾�� ������ ����ڰ� ���翩�� ( 0: ����, 1: ������ )
		if (strcmp(message.contents, "1") == 0)
		{
			write(client, 3);
		}
		else
		{
			printf("������ �������� �ʽ��ϴ�.\n");
			shared_diary(client);
		}
	}

	else if (strcmp(message.header, "writeSharedEnd") == 0) {	//���� ���̾ �ۼ� �Ϸ�
		printf("\n\n* ���̾ �ۼ��� �Ϸ�Ǿ����ϴ� *\n");
		shared_diary(client);
	}

	else if (strcmp(message.header, "noAL") == 0) {		//no alone list : ȥ�ھ��⿡�� �� �ϱⰡ ����
		//aloneMenue ȥ�� ���� �޴��� ����
		printf("%s\n", message.contents);
		Priv_diary(client);
	}

	else if (strcmp(message.header, "ALing") == 0) {
		//���� �̸��� �޴� �� -> index�� ���� �̸� �߶� ���
		char arg[2][4096];	//�ڸ� �迭 ����
		client.parse_msg((const char*)message.contents, 2, arg[0], arg[1]);	//�ڸ���
		printf("%s. %s\n", arg[0], arg[1]);
	}

	else if (strcmp(message.header, "ALend") == 0) {
		//��� ��� �� -> ȥ�� �б� -> �б� �޴� ���
		aloneReadMenue(client);
	}

	else if (strcmp(message.header, "noAFerr") == 0) {
		//���� ����, ���� ������ ���� err ���
		printf("%s\n", message.contents);
		aloneReadMenue(client);
	}

	else if (strcmp(message.header, "readAF") == 0) {
		/* ������ ���� ���� ������ ����
		1. ����Ű�� ��ȣȭ�� �ϱ� ������ ��ȣȭ
		2. ���
		3. wait -> ���� ���� ���̾ �޴��� ���ư�
		*/

		//printf("%s\n", message.contents);
	    //constents : 1. ��ȣ�� 2. ��ȣȭ�� txt�� ����(��ȣȭ�� ����)
		char arg[2][5000];   //�ڸ� �迭 ����
		//�ڸ��� : arg[0] : ��ȣ��, arg[1] : ��ȣȭ�� txt����
		client.parse_msg(message.contents, 2, arg[0], arg[1]);
	
		char buffer[4096];   //��ȣȭ�� ��ȣȭ�� ���� �ִ� ����

		strcpy(buffer, msg_decrypt(client, arg[0], atoi(arg[1]), client.sym_key));

		printf("-----------------------------------------------------------\n");
		printf("%s\n", buffer);
		printf("-----------------------------------------------------------\n");
		printf("�������� ���ư��÷��� �ƹ�Ű�� �����ּ���.\n");

		while (1) {
			if (kbhit()) {
				getch();
				break;
			}
		}
		Priv_diary(client);
	}

	else if (strcmp(message.header, "back2priv") == 0)  //���δ��̾ �޴��� ���ư���
	{
		Priv_diary(client);
	}

	else if (strcmp(message.header, "diaryShared") == 0) //�������̾ �޴��� �б�
	{
	shared_diary(client);
	}

	else if (strcmp(message.header, "back2shrd") == 0)  //�������̾ �޴��� ���ư���
	{
		shared_diary(client);
	}

	else if (strcmp(message.header, "getShareListErr") == 0) {
		//������ ���̾ ����Ʈ ��¿� ���� ���� ���
	
		printf("%s\n", message.contents);
		shared_diary(client);
	}

	else if (strcmp(message.header, "shareListIng") == 0) {
		/*	���� ���̾�� ����Ʈ ��� - ����ϴ� ��	*/

		char arg[2][4096];	//�߶�� �����
		//arg[0] : index, arg[1] : ���� �̸�
		client.parse_msg(message.contents, 2, arg[0], arg[1]);
		printf("%s. %s\n", arg[0], arg[1]);
	}
	else if (strcmp(message.header, "readSListEnd") == 0) {
		sharedReadMenue(client);
	}

	else if (strcmp(message.header, "getShareFileErr") == 0) {
		/*	���� ���̾ �б� ����	�޽��� ���
		-> ���� ���̾ �޴��� ���ư�
		*/
		
		printf("%s\n", message.contents);	//���� �޽��� ���
		shared_diary(client);	//���� ���̾ �޴��� ���ư�
	}

	else if (strcmp(message.header, "readSFileEnd") == 0) {
		/* ������ ���� ���� ������ ����
		1. ����Ű�� ��ȣȭ�� �ϱ� ������ ��ȣȭ
		2. ���
		3. wait -> ���� ���� ���̾ �޴��� ���ư�
		*/
		
		char arg[2][4096];   //�ڸ� �迭 ����
		//�ڸ��� : arg[0] : ��ȣ��, arg[1] : ��ȣȭ�� txt����
		client.parse_msg(message.contents, 2, arg[0], arg[1]);

		char buffer[4096];   //��ȣȭ�� ��ȣȭ�� ���� �ִ� ����

		strcpy(buffer, msg_decrypt(client, arg[0], atoi(arg[1]), client.sym_key));

		printf("-----------------------------------------------------------\n");
		printf("%s\n", buffer);
		printf("-----------------------------------------------------------\n");
		printf("�������� ���ư��÷��� �ƹ�Ű�� �����ּ���.\n");

		while (1) {
			if (kbhit()) {
				getch();
				break;
			}
		}
		shared_diary(client);
	}

	else if (strcmp(message.header, "back2main") == 0)	//�������� ���ư���
	{
	main_menu(client);
	}

	else if (strcmp(message.header, "logout") == 0) //�α׾ƿ� ����
	{
		printf("\n* �α׾ƿ� ����! *\n");
		init(client);
	}
}


/* ���� ���̾ �б� �޴� 1. �б� 2. �ڷΰ���
1. ���� ���� ��ȣ�� �Է� ���� -> ���� ��ȣ�� �������� ����
2. �ڷΰ��� -> ���� ���̾ �޴��� ���ư�
*/
void aloneReadMenue(AuthClient& client) {
	printf("-----------------------\n");
	printf("1. �б�\n");
	printf("2. �ڷΰ���\n");
	printf("-----------------------\n");

	int cmd;
	printf(">> ");
	scanf("%d", &cmd);

	switch (cmd)
	{
	case 1:
		printf("���� ���� ��ȣ�� �Է����ּ��� : ");
		int number;
		char numberStr[20];
		scanf("%d", &number);
		sprintf(numberStr, "%d", number);
		//��ȣ ������
		client.send_msg("readAF", 1, (const char*)numberStr);
		break;
	case 2:
		client.send_msg("back2priv", 1, "0");
		break;
	}
}

/* ���� ���̾ �б� �޴� 1. �б� 2. �ڷΰ���
1. ���� ���� ��ȣ�� �Է� ���� -> ���� ��ȣ�� �������� ����
2. �ڷΰ��� -> ���� ���̾ �޴��� ���ư�
*/
void sharedReadMenue(AuthClient& client) {
	printf("-----------------------\n");
	printf("1. �б�\n");
	printf("2. �ڷΰ���\n");
	printf("-----------------------\n");

	int cmd;
	printf(">> ");
	scanf("%d", &cmd);

	switch (cmd)
	{
	case 1:
		printf("���� ���� ��ȣ�� �Է����ּ��� : ");
		int number;
		char numberStr[20];
		scanf("%d", &number);
		sprintf(numberStr, "%d", number);
		//��ȣ ������
		client.send_msg("readShareFile", 1, (const char*)numberStr);
		break;
	case 2:
		client.send_msg("back2shrd", 1, "0");
		break;
	}
}