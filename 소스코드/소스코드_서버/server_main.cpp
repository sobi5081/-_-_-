#include "openssl_fn.h"
#include <openssl/applink.c>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcryptoMD.lib")
#pragma comment(lib, "libsslMD.lib")

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define TIMESKEW 2
#define RSA_ALGORITHM_H

#define ID_LEN 32
#define PW_LEN 32
#define NAME_LEN 32
#define HASH_RESULT_LEN 41
#define HEADER_SIZE 8
#define CONTENTS_LEN 128
#define FILE_LEN 40
#define CONTENTS_SIZE 128

using namespace std;

void readAloneFiles(AuthServer* server, char* userID);
int countFiles(char* userID, const char* folderName);
int getFileEncrypted(char* path, char* plainText);
char* login(AuthServer* server, char* userID);
char* msg_encrypt(AuthServer& server, const char* contents, int& len, char* key);
char* msg_decrypt(AuthServer& server, const char* contents, int len, char* key);
void process(AuthServer* server);


/*�����Լ�. ���� ��ü ���� �� ������ ���� �޽��� ó�� �Լ� ������ ����.
*parameter: ����
*return: ���� �ڵ�
*/
int main()
{
	AuthServer aa(50000); //
	std::thread* th;
	th = new std::thread(process, &aa);

	aa.wait();

	return 0;
}

/* <�α���>
1.���Ͽ��� ������� N�� �ؽ��� ���� �޾ƿ���, ����ڰ� n-1�� �ؽ��� ���� �޾� 1�� �ؽ��Ͽ� �� ���� ��
  1) ������ �α��� ����  -> n-1, n-1�� �ؽ��� ���� ������ ����� ������ �����ϰ� �ٽ� ����� ����
  2) �ٸ��� �α��� ����  -> ������ �̷������ ����
2. ��ĪŰ return
*/
char* login(AuthServer* server, char* userID) {
	char path[FILE_LEN];   //���� ��ġ
	FILE* fp;   //���� ������
	//������ ���Ͽ��� �޾ƿ� ���� ����
	int userN = 0;   //������� N
	char fileHash[HASH_RESULT_LEN] = "";   //���Ͽ��� �ؽ� N�� �� ���� �޾ƿ�            
	char userHash[HASH_RESULT_LEN] = "";   //����ڰ� ���� ��Ŷ���� �޾ƿ� n-1�� �ؽ��� �� -> ���� ������Ʈ ��(�����ϰ� ���� ����)
	char userHash_[HASH_RESULT_LEN] = "";   //����ڰ� ���� �ؽð��� �ؽ� �� �� �� �ϱ�

	char aa[3][4096];
	char final_buf[128];
	server->parse_msg(server->peekMessage().msg.contents, 3, aa[0], aa[1], aa[2]);
	privateDecrypt(atoi(aa[1]), decode64((unsigned char*)aa[2], 2048), final_buf);

	//���� contents���� n-1�� �ؽ��� �� �о����
	strcpy(userHash, aa[0]);

	printf("\n<������ ���� �κ�>\n");
	printf("n-1�� �ؽð� : %s\n", userHash);

	//�ؽ� 1�� �� �ϱ�
	hasing((char*)userHash, (char*)userHash_, 1);

	printf("\nŬ���̾�Ʈ�� ���� n-1�� �ؽð��� �ѹ� �� �ؽ��� �� : %s\n", userHash_);

	//���� path ����� : path = "user\" + userID + ".txt"
	strcpy(path, "user\\");
	strcat(path, userID);

	strcat(path, ".txt");

	//printf("����� ���� ���� ��� : %s\n", path);

	//���� ����
	fp = fopen(path, "r");
	fscanf(fp, "%d", &userN);   //N�� �޾ƿ�
	fscanf(fp, "%s", fileHash);   //n�� �ؽ��� �� �޾ƿ�

	//���� �ݱ�
	fclose(fp);

	if (strcmp(userHash_, fileHash) == 0)
	{
		//�α��� ����
		//n�� n���� �ؽð��� n-1�� n-1�� �ؽ��� ������ ����
		ofstream fs;
		fs.open(path, ios::out | ios::trunc);
		fs << userN - 1 << endl << userHash;
		fs.close();
		printf("\n<����� ���� ����>\n");
		printf("n : %d\n�ؽð� : %s\n��\n", userN, fileHash);
		printf("n : %d\n�ؽð� : %s\n", userN - 1, userHash_);
		AuthServer::send_msg(server->peekMessage().sock, "login", 1, "1");
	}
	else
	{
		//��й�ȣ Ʋ��
		AuthServer::send_msg(server->peekMessage().sock, "login", 1, "2");
	}
	return final_buf;
}


/*���̾ ������ ��ĪŰ�� ��ȣȭ�� ��, Base64���ڵ�.
*parameter: ���� ��ü, ��ȣȭ�� ����, ��ȣ���� ����, Ŭ���̾�Ʈ���� ��ĪŰ
*return: base64 ���ڵ� �� ���ڿ�
*/
char* msg_encrypt(AuthServer& server, const char* contents, int& len, char* key) //��ȣ���� ���̵� �˾Ƶ־� ��
{
	//printf("��ȣȭ! ������� ��ĪŰ : %s\n", key);
	int lena;
	unsigned char buf[2048];
	memset(buf, 0, 2048);
	lena = server.encrypt_block(buf, (unsigned char*)contents, strlen((char*)contents), (unsigned char*)key);
	buf[lena] = 0;

	len = lena;

	return base64((unsigned char*)buf, 2048, lena);
}


/*Ŭ���̾�Ʈ�κ��� ���� base64 ���ڵ� �� ���̾ ������ ���ڵ� �� ��, Ŭ���̾�Ʈ���� ��ĪŰ�� ��ȣȭ.
*parameter: ���� ��ü, base64�� ����
*return: ��ȣȭ�� ���ڿ�
*/
char* msg_decrypt(AuthServer& server, const char* contents, int len, char* key)
{
	//printf("��ȣȭ! ������� ��ĪŰ : %s\n", key);
	int lena;
	char buf[2048];
	unsigned char buf2[2048];
	memcpy(buf, decode64((unsigned char*)contents, 2048), len);
	lena = server.decrypt_block(buf2, (unsigned char*)buf, len, (unsigned char*)key);
	buf2[lena] = 0;

	return (char*)buf2;
}


/*ť�� �ֻ��� �޽����� �о� ����� Ȯ�� �� �ش� ������� �б�.
*parameter: ���� ��ü
*return: ����
*/
void process(AuthServer* server)
{
	char userID[ID_LEN];	//������ id
	char sym_key[64]; //������ �����ϴ� ��ĪŰ

	while (1)
	{
		if (server->isEmpty() == false)
		{
			if (strcmp(server->peekMessage().msg.header, "loginID") == 0) {
				/*
					client�κ��� �α��� �� ID�� ����
					���� ������ '������̸�.txt'�� ����Ǿ� ���� -> ���� �̸����� �˻��Ͽ� ȸ�� ���� �Ǵ�
					1) ȸ�� O -> ������� ������ �о� N�� client���� ����
					2) ȸ�� X -> ����ڰ� �ƴ��� client���� ����
				*/

				//id�� �޾Ƽ� ���� �ִ��� �˻�
				char arg[1][4096];
				//contents�ȿ� �ִ� id ������

				server->parse_msg(server->peekMessage().msg.contents, 1, arg[0]);


				//���� ����
				strcpy(userID, arg[0]);
				printf("id : %s\n", userID);

				std::string path = "user\\";
				path += userID;
				path += ".txt";
				if (access(path.c_str(), 0) == 0)	//���� ����
				{

					printf("���� ã��\n");
					//���Ͽ��� n �б�
					char N[CONTENTS_SIZE];	//���Ͽ��� �о�� N
					FILE* fp;	//���� ������
					fp = fopen(path.c_str(), "r");
					fscanf(fp, "%s", N);

					printf("���� ������ n�� : %s\n", N);
					fclose(fp);

					//���� ���Ͽ��� n�� ����
					AuthServer::send_msg(server->peekMessage().sock, "loginN", 1, N);
				}
				else {//id ���� -> id���� �������� ���� ���� ����

					AuthServer::send_msg(server->peekMessage().sock, "login", 1, "0");
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "login") == 0)
			{
				/*
				����ڰ� PW�� ������
				-> login �Լ��� ȣ�� -> ����Ű�� return�޾� ����
				*/

				strcpy(sym_key, login(server, (char*)userID));
			}

			else if (strcmp(server->peekMessage().msg.header, "join") == 0) //ȸ������ ��û ó��
			{
				char* buf;
				char tmp[4096];
				int len;
				int public_len;
				char arg[7][4096];
				char final_buf[4096];
				char lf[3] = "\n";
				FILE* fp;
				std::string file;

				server->parse_msg(server->peekMessage().msg.contents, 2, arg[0], arg[1]);

				file = "user\\";
				file += arg[0];
				file += ".txt";
				fp = fopen(file.c_str(), "w");
				fwrite("100", sizeof(char), strlen("100"), fp); fwrite(lf, sizeof(char), strlen(lf), fp);
				fwrite(arg[1], sizeof(char), strlen(arg[1]), fp); fwrite(lf, sizeof(char), strlen(lf), fp);

				fclose(fp);

				AuthServer::send_msg(server->peekMessage().sock, "joinEnd", 1, "0");
				printf("��");
			}

			else if (strcmp(server->peekMessage().msg.header, "diaryPriv") == 0) //���� ���̾ ���� �� �ش� �޴��� �б� �޽��� ����
			{
				AuthServer::send_msg(server->peekMessage().sock, "diaryPriv", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "writeSha_chk") == 0) //���̾ ���� ��� ���� ���� Ȯ��
			{
				char arg[1][128];
				server->parse_msg(server->peekMessage().msg.contents, 1, arg[0]);
				char path[64];
				sprintf(path, "user\\%s.txt", arg[0]);
				if (access(path, 0) == 0)	//���� ����
				{
					AuthServer::send_msg(server->peekMessage().sock, "writeSha_chk_rt", 1, "1");
				}
				else {//id ���� -> id���� �������� ���� ���� ����

					AuthServer::send_msg(server->peekMessage().sock, "writeSha_chk_rt", 1, "0");
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "writePriv") == 0) //Ŭ���̾�Ʈ�κ��� ������ ���� ���̾ ��ȣȭ �� ��ȣȭ�ؼ� ����
			{
				char aa[3][1024];

				server->parse_msg(server->peekMessage().msg.contents, 3, aa[0], aa[1], aa[2]);
				printf("\n<Ŭ���̾�Ʈ�� ���� ��ȣȭ�� ���̾ ����>\n%s\n", aa[1]);

				if (strcmp(aa[0], "1") == 0)
					//���� ���̾ �޾ƿͼ� ���Ϸ� ����
				{
					char path[FILE_LEN];
					FILE* fp;
					char result_buf[4096];
					char result_buf2[4096];
					char result_buf3[4096];
					char final[4096];

					int result_len;
					int len;
					std::string check_index;
					char buf[64];

					for (int i = 1;; i++) {
						sprintf(buf, "private_diary\\%s_%d.txt", userID, i);
						if (access(buf, 0) != 0)
							break;
					}

					//��ȣȭ�Ѱ� ��ȣȭ �ؼ� result_buf�� �־���
					strcpy(result_buf, msg_decrypt(*server, aa[1], atoi(aa[2]), server->peekMessage().sym_key));
					//aa[1] : ��ȣ��, aa[2] : ��ȣ�� ���� -> �� �� ������ ��ȣȭ ��
					printf("\n��ȣȭ�� ���̾ ���� : %s\n", result_buf);

					fp = fopen(buf, "w");
					len = publicEncrypt(result_buf, result_buf2);
					//���� ����Ű�� �ٽ� ��ȣȭ
					//printf("�׽�Ʈ : %d", len);
					sprintf(buf, "%d\n", len);

					fwrite(buf, sizeof(char), strlen((char*)buf), fp);

					fwrite(base64((unsigned char*)result_buf2, 1024, result_len), sizeof(char), strlen((char*)base64((unsigned char*)result_buf2, 1024, result_len)), fp);
					//base64 ���ڵ� �ؼ� ���Ͽ� ���� ����

					fclose(fp);

					AuthServer::send_msg(server->peekMessage().sock, "writePrivEnd", 1, "0");

				}
				else if (strcmp(server->peekMessage().msg.contents, "2") == 0)
					AuthServer::send_msg(server->peekMessage().sock, "diaryPriv", 1, "2");

			}

			else if (strcmp(server->peekMessage().msg.header, "writeShared") == 0) // //Ŭ���̾�Ʈ�κ��� ������ ���� ���̾ ��ȣȭ �� ��ȣȭ�ؼ� ����
			{
				char aa[3][1024];

				server->parse_msg(server->peekMessage().msg.contents, 3, aa[0], aa[1], aa[2]);
				printf("\n<Ŭ���̾�Ʈ�� ���� ��ȣȭ�� ���̾ ����>\n%s\n", aa[1]);

				char path[FILE_LEN];
				FILE* fp;
				char result_buf[4096];
				char result_buf2[4096];
				char result_buf3[4096];
				char final[4096];

				int result_len;
				int len;
				std::string check_index;
				char buf[64];

				for (int i = 1;; i++) {
					sprintf(buf, "shared_diary\\%s_%s_%d.txt", userID, aa[0], i);

					if (access(buf, 0) != 0)
						break;
				}

				//��ȣȭ�Ѱ� ��ȣȭ �ؼ� result_buf�� �־���
				strcpy(result_buf, msg_decrypt(*server, aa[1], atoi(aa[2]), server->peekMessage().sym_key));
				//aa[1] : ��ȣ��, aa[2] : ��ȣ�� ���� -> �� �� ������ ��ȣȭ ��
				printf("\n��ȣȭ�� ���̾ ���� : %s\n", result_buf);

				fp = fopen(buf, "w");
				len = publicEncrypt(result_buf, result_buf2);
				//���� ����Ű�� �ٽ� ��ȣȭ
				//printf("�׽�Ʈ : %d", len);
				sprintf(buf, "%d\n", len);

				fwrite(buf, sizeof(char), strlen((char*)buf), fp);

				fwrite(base64((unsigned char*)result_buf2, 1024, result_len), sizeof(char), strlen((char*)base64((unsigned char*)result_buf2, 1024, result_len)), fp);
				//base64 ���ڵ� �ؼ� ���Ͽ� ���� ����

				fclose(fp);

				AuthServer::send_msg(server->peekMessage().sock, "writeSharedEnd", 1, "0");
			}

			else if (strcmp(server->peekMessage().msg.header, "readAL") == 0) {	//read alone liist
				/*���� �ϱ� ����Ʈ client���� ������*/
			
				readAloneFiles(server, userID);
			}

			else if (strcmp(server->peekMessage().msg.header, "readAF") == 0) {
				/* ȥ�ھ� �ϱ� ������ �д´�
				1. client�� �о�� ���� index�� ���� -> ���� �̸� ���� ���� open
				  1) ���� ���� -> ������ ����Ű�� ��ȣȭ �Ǿ� �ִ� ������ ����Ű�� ��ȣȭ�Ͽ� ����Ű�� ��ȣȭ�Ͽ� ����
				  2) ���� ���� -> ���� �޽���
				  3) ���� ���� ���� -> ���� �޽���
				*/


				//client�� ���� ��ȣ�� ������ ����
				char* indexStr = server->peekMessage().msg.contents;   //��ȣ �о��
				char path[FILE_LEN] = "";   //���� ���

				//���� ��� ����� : ������ + ����id + "_" + index + ".txt"
				strcpy(path, "private_diary\\");
				strcat(path, userID);
				strcat(path, "_");
				strcat(path, indexStr);
				strcat(path, ".txt");

				printf("%s\n", path);

				//������ ����
				if (access(path, 0) != 0) {
					//client�� �߸��� index�� ����(���� ����) -> no alone file err
					AuthServer::send_msg(server->peekMessage().sock, "noAFerr", 1, "������ �������� �ʽ��ϴ�.");
				}
				//��ȣȭ�� ������ ��ȣȭ �Ͽ� �о��
				char plainText[BUFFSZ];
				int check = getFileEncrypted(path, plainText);

				if (check == -1) {//���� ���� ����
					AuthServer::send_msg(server->peekMessage().sock, "noAFerr", 1, "������ �������� �ʽ��ϴ�.");
				}
				else if (check == -2) {//���� ���� ����
					AuthServer::send_msg(server->peekMessage().sock, "noAFerr", 1, "���� ������ �����ϴ�.");
				}
				else {//��������
					//��ȣȭ + ���ڵ� �ؼ� ����
					int encyptLen; //��ȣ���� ���� ���� ���� ������ְ�
					char tmp_buf[3000]; // ��ȣ�� ���� ��
					char tmp_buf2[32]; //��ȣ�� ����(= encyptLen) ���� ��

					strcpy(tmp_buf, msg_encrypt(*server, plainText, encyptLen, server->peekMessage().sym_key)); //��ȣȭ�ؼ� tmp_buf�� ����
					sprintf(tmp_buf2, "%d", encyptLen); //��ȣ���� ���̸� tmp_buf2�� �־���
					//�Ű����� 2�� : 1. ��ȣ�� 2. ��ȣ�� ����
					AuthServer::send_msg(server->peekMessage().sock, "readAF", 2, tmp_buf, tmp_buf2);

				}


			}

			else if (strcmp(server->peekMessage().msg.header, "back2priv") == 0)  //���� ���̾ �޴��� ���ư��� ���� �� �ش� �޴��� �б� �޽��� ����
			{
				AuthServer::send_msg(server->peekMessage().sock, "back2priv", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "back2main") == 0)  //���� �޴��� ���ư��� ���� �� �ش� �޴��� �б� �޽��� ����
			{
				AuthServer::send_msg(server->peekMessage().sock, "back2main", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "diaryShared") == 0)  //���� ���̾ ���� �� �ش� �޴��� �б� �޽��� ����
			{
				AuthServer::send_msg(server->peekMessage().sock, "diaryShared", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "readShareList") == 0) {
				/* �λ���� �����ϴ� �����ϱ� ���� ����Ʈ ������
				- ���� ���� �̸� : 'shared_diary'
				- ���� ���� �̸� : '�����1_�����2_index.txt'
				1. ������� ���� �̸��� ���Ե� txt������ �����ϴ��� �˾Ƴ�
				  1) ���� X : �����޽���
				  2) ���� O : ���� ���� �ϳ��� ���� -> �� ������ ���� ������ ���� �������� �˸�
				*/

				_finddata_t fd;	//������ �������� �����ϴ� ����ü
				long handle;	//���� �˻� ��� �� ���� -1 : ���ǿ� �´� ���� ����, 0 : ���� ����
				//ù ���� �˻�
				char pathSpec[FILE_LEN] = "";
				sprintf(pathSpec, "shared_diary\\*%s*.txt", userID);
				handle = _findfirst(pathSpec, &fd);

				if (handle == -1) {//���� ���� ����
					AuthServer::send_msg(server->peekMessage().sock, "getShareListErr", 1, "\n�ۼ��� ���� �ϱⰡ �������� �ʽ��ϴ�.");
				}
				else {//���� �����Ƿ� �ٸ� ���ϵ� �˻� �غ�
					int count = 0;	//���� ���� count
					char countStr[30];	//count�� string����

					do {
						count++;
						sprintf(countStr, "%d", count);
						printf("%s.%s\n", countStr, fd.name);
						//index, ���� �̸� ������
						AuthServer::send_msg(server->peekMessage().sock, "shareListIng", 2, countStr, fd.name);
					} while (_findnext(handle, &fd) == 0);
					//���� ����Ʈ �� ���� : read shared list end
					AuthServer::send_msg(server->peekMessage().sock, "readSListEnd", 1, "0");
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "readShareFile") == 0) {
				/* ����ڰ� ���ϴ� ������ ��� ����
				- ���� ���� �̸� : 'shared_diary'
				- ���� ���� �̸� : '�����1_�����2_index.txt'
				1. ����ڴ� ������ index�� ����
				2. ����� ID�� ���� �˻��ϸ鼭 count�Ͽ� ����ڰ� ���� index�� �������� ���� ó��
				  1) ���� ���� : ������ ����Ű�� ��ȣȭ�� ������ ����Ű�� ��ȣȭ�Ͽ� �ٽ� ����Ű�� ��ȣȭ�Ͽ� ����
				  2) ���� ���� : �����޽���
				  3) ���� ���� ���� : �����޽���
				*/

				_finddata_t fd;	//������ �������� �����ϴ� ����ü
				long handle;	//���� �˻� ��� �� ���� -1 : ���ǿ� �´� ���� ����, 0 : ���� ����
				//ù ���� �˻�
				char pathSpec[FILE_LEN] = "";	//�˻��� spec
				sprintf(pathSpec, "shared_diary\\*%s*.txt", userID);
				handle = _findfirst(pathSpec, &fd);

				if (handle == -1) {//���� ���� ����
					AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "������ �������� �ʽ��ϴ�.1\n");
				}
				else {//���� �����Ƿ� �ٸ� ���ϵ� �˻� �غ�
					int count = 0;	//���� ���� count
					char countStr[30];	//count�� string����

					do {
						count++;
						sprintf(countStr, "%d", count);
						printf("%s.%s\n", countStr, fd.name);
						if (strcmp(countStr, server->peekMessage().msg.contents) == 0) {
							//���� �ε�����° ���� ó��
							//��ȣȭ�� ������ ��ȣȭ �Ͽ� �о��
							char plainText[BUFFSZ];
							char path[BUFFSZ];	//���� ���
							strcpy(path, "shared_diary\\");
							strcat(path, fd.name);
							int check = getFileEncrypted(path, plainText);

							if (check == -1) {//���� ���� ����
								AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "������ �������� �ʽ��ϴ�.2");
								break;
							}
							else if (check == -2) {//���� ���� ����
								AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "���� ������ �����ϴ�.");
								break;
							}
							else {//��������
							   //��ȣȭ + ���ڵ� �ؼ� ����
								int encyptLen; //��ȣ���� ���� ���� ����
								char tmp_buf[3000]; // ��ȣ�� ���� ��
								char tmp_buf2[32]; //��ȣ�� ����(= encyptLen) ���� ��

								strcpy(tmp_buf, msg_encrypt(*server, plainText, encyptLen, server->peekMessage().sym_key)); //��ȣȭ�ؼ� tmp_buf�� ����
								sprintf(tmp_buf2, "%d", encyptLen); //��ȣ���� ���̸� tmp_buf2�� �־���

								//read shared file end -> �Ű����� 2�� : 1. ��ȣ�� 2. ��ȣ�� ����
								AuthServer::send_msg(server->peekMessage().sock, "readSFileEnd", 2, tmp_buf, tmp_buf2);
								break;
							}
						}
					} while (_findnext(handle, &fd) == 0);

					if (count < atoi(server->peekMessage().msg.contents)) {
						//client�� ���� index�� ������ �ְ� index���� ŭ -> get shared file err
						AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "������ �������� �ʽ��ϴ�.3");
					}
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "back2shrd") == 0)  //���� ���̾�� ���ư��� ���� �� �ش� �޴��� �б� �޽��� ����
			{
				AuthServer::send_msg(server->peekMessage().sock, "back2shrd", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "logout") == 0) { //�α׾ƿ�
				//strcpy(sym_key, "0");
				AuthServer::send_msg(server->peekMessage().sock, "logout", 1, "0");
			}

			server->popMessage();
		}
	}
}



/*
ȥ�ھ��� ������ ���� ����Ʈ client���� ������
- ȥ�ھ��� �ϴ� ���� �̸� : 'private_diary'
- ȥ�ھ��� �ϸ� ����� ���� �̸� : ������̸�_index.txt
1. �����ID�� �� txt������ ������ count
  1) 0�� -> ���� ���� -> ���� �޽��� �۽�
  2) n�� -> �ٽ� ���� �����ϴ��� �˻��ϸ� ���� �̸� ���� -> ���� �� ������ ���� �������� �˸�
*/
void readAloneFiles(AuthServer* server, char* userID) {
	//���� ��� 1~... ���� ������ �� index���ϱ�
	char path[FILE_LEN];   //���� ��ġ
	int index = 0;   //����ִ� ���� ���� count
	char indexStr[10] = "";   // index ���� ���� ���ڿ���

	index = countFiles(userID, "private_diary\\");

	printf("\nã�� ������ ���� : %d\n", index);

	if (index == 0) {//index = 0 : ���� ����Ʈ ����
	   //���� ������ "�ۼ��� �ϱⰡ �����ϴ�." �޽����� �ش�. -> �׸��� ������ ȥ�ھ��� �޴��� ���ư�
		AuthServer::send_msg(server->peekMessage().sock, "noAL", 1, "�ۼ��� �ϱⰡ �����ϴ�.\n");   //there is no Alone List
	}
	else {//������ 1�� �̻� �ִ�
	   //���� �̸� �ϳ��ϳ� ���� ����
		for (int i = 0; i < index; i++) {
			//���� �̸� ����
			strcpy(path, "");   //�ʱ�ȭ
			//����id + "_index" + ".txt"
			strcpy(path, userID);   //���� id
			strcat(path, "_");

			strcpy(indexStr, "");   //index string�ʱ�ȭ
			sprintf(indexStr, "%d", i + 1);   //������ �迭�� �ٲ�

			strcat(path, indexStr);   //index
			strcat(path, ".txt");   //.txt

			//printf("%s\n", path);

			//alone list reading(��� ������ ��) -> ���� ��� ������ ���� -> client������ �޾Ƽ� ��¸� ��
			// (index + �����̸�) ����
			AuthServer::send_msg(server->peekMessage().sock, "ALing", 2, (const char*)indexStr, (const char*)path);
		}
		//���� �̸� ������ ���� �������� �˸� -> ������ ���� �޴��� �Ѿ
		AuthServer::send_msg(server->peekMessage().sock, "ALend", 1, "0");
	}
}


/* ���� ���� count�ؼ� ����
�����ID + index������ ���� �̸� ����� ������ count�ؼ� ����
*/
int countFiles(char* userID, const char* folderName) {
	char indexStr[10] = "";
	char path[FILE_LEN];
	int count = 0;

	do {
		strcpy(path, "");   //�ʱ�ȭ
		//�����̸� + ����id + "_index" + ".txt"
		strcpy(path, folderName);   //����
		strcat(path, userID);   //���� id
		strcat(path, "_");

		strcpy(indexStr, "");   //index string�ʱ�ȭ
		sprintf(indexStr, "%d", count + 1);

		strcat(path, indexStr);   //index
		strcat(path, ".txt");   //.txt
		count++;      //count����
	} while (access(path, 0) == 0);

	return count - 1;
	//������ ������ count = 1������ ������ ������ ���� -1 ����
	//0 : �� ó����, -1 : ���� ���� ����, -2 : ���� ������ �����ϴ�.
}


// ������ ����Ű�� ��ȣȭ�� txt������ �о�ͼ� ���ڵ�+��ȣȭ = ��
int getFileEncrypted(char* path, char* plainText) {
	int len;
	char result_buf[4096];
	//char result[4096] = "";
	char ch;
	char* p = result_buf;
	FILE* fp;

	fp = fopen(path, "r");
	if (fp == NULL) {	//���� open ����
		printf("���� ���� ����\n");
		return -1;
	}

	fscanf(fp, "%s", result_buf);
	if (strlen(result_buf) < 0) {	//���� ������ �������� ����
		printf("���� ������ ����\n");
		return -2;
	}

	len = atoi(result_buf);
	printf("\n<���� ������ �ִ� ������� ��ȣȭ�� ���̾ ����>\n");
	while (1) {
		ch = fgetc(fp);
		if (feof(fp)) break;
		*(p++) = ch;
		printf("%c", ch);
	}
	*p = 0;
	printf("\n");
	fclose(fp);

	privateDecrypt(len, decode64((unsigned char*)result_buf, 2048), plainText);

	printf("\n���� �������� ������� ���� ��ȣȭ : %s\n", plainText);

	return 0;	//���� ����
}