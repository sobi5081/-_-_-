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


/*메인함수. 서버 객체 생성 및 서버를 열고 메시지 처리 함수 스레드 생성.
*parameter: 없음
*return: 종료 코드
*/
int main()
{
	AuthServer aa(50000); //
	std::thread* th;
	th = new std::thread(process, &aa);

	aa.wait();

	return 0;
}

/* <로그인>
1.파일에서 사용자의 N번 해시한 값을 받아오고, 사용자가 n-1번 해시한 값을 받아 1번 해시하여 그 값과 비교
  1) 같으면 로그인 성공  -> n-1, n-1번 해시한 값을 이전의 사용자 파일을 삭제하고 다시 만들어 저장
  2) 다르면 로그인 실패  -> 저장이 이루어지지 않음
2. 대칭키 return
*/
char* login(AuthServer* server, char* userID) {
	char path[FILE_LEN];   //파일 위치
	FILE* fp;   //파일 포인터
	//유저의 파일에서 받아올 내용 변수
	int userN = 0;   //사용자의 N
	char fileHash[HASH_RESULT_LEN] = "";   //파일에서 해시 N번 한 것을 받아옴            
	char userHash[HASH_RESULT_LEN] = "";   //사용자가 보낸 패킷에서 받아온 n-1번 해시한 값 -> 파일 업데이트 함(삭제하고 새로 만듬)
	char userHash_[HASH_RESULT_LEN] = "";   //사용자가 보낸 해시값에 해시 한 번 더 하기

	char aa[3][4096];
	char final_buf[128];
	server->parse_msg(server->peekMessage().msg.contents, 3, aa[0], aa[1], aa[2]);
	privateDecrypt(atoi(aa[1]), decode64((unsigned char*)aa[2], 2048), final_buf);

	//소켓 contents에서 n-1번 해시한 값 읽어오기
	strcpy(userHash, aa[0]);

	printf("\n<유저가 보낸 부분>\n");
	printf("n-1번 해시값 : %s\n", userHash);

	//해시 1번 더 하기
	hasing((char*)userHash, (char*)userHash_, 1);

	printf("\n클라이언트가 보낸 n-1번 해시값에 한번 더 해시한 값 : %s\n", userHash_);

	//파일 path 만들기 : path = "user\" + userID + ".txt"
	strcpy(path, "user\\");
	strcat(path, userID);

	strcat(path, ".txt");

	//printf("사용자 정보 파일 경로 : %s\n", path);

	//파일 열기
	fp = fopen(path, "r");
	fscanf(fp, "%d", &userN);   //N값 받아옴
	fscanf(fp, "%s", fileHash);   //n번 해시한 값 받아옴

	//파일 닫기
	fclose(fp);

	if (strcmp(userHash_, fileHash) == 0)
	{
		//로그인 성공
		//n과 n번한 해시값을 n-1과 n-1번 해시한 값으로 변경
		ofstream fs;
		fs.open(path, ios::out | ios::trunc);
		fs << userN - 1 << endl << userHash;
		fs.close();
		printf("\n<사용자 파일 변경>\n");
		printf("n : %d\n해시값 : %s\n↓\n", userN, fileHash);
		printf("n : %d\n해시값 : %s\n", userN - 1, userHash_);
		AuthServer::send_msg(server->peekMessage().sock, "login", 1, "1");
	}
	else
	{
		//비밀번호 틀림
		AuthServer::send_msg(server->peekMessage().sock, "login", 1, "2");
	}
	return final_buf;
}


/*다이어리 내용을 대칭키로 암호화한 후, Base64인코딩.
*parameter: 서버 객체, 암호화할 내용, 암호문의 길이, 클라이언트와의 대칭키
*return: base64 인코딩 된 문자열
*/
char* msg_encrypt(AuthServer& server, const char* contents, int& len, char* key) //암호문의 길이도 알아둬야 함
{
	//printf("암호화! 사용중인 대칭키 : %s\n", key);
	int lena;
	unsigned char buf[2048];
	memset(buf, 0, 2048);
	lena = server.encrypt_block(buf, (unsigned char*)contents, strlen((char*)contents), (unsigned char*)key);
	buf[lena] = 0;

	len = lena;

	return base64((unsigned char*)buf, 2048, lena);
}


/*클라이언트로부터 받은 base64 인코딩 된 다이어리 내용을 디코딩 한 후, 클라이언트와의 대칭키로 복호화.
*parameter: 서버 객체, base64된 내용
*return: 복호화된 문자열
*/
char* msg_decrypt(AuthServer& server, const char* contents, int len, char* key)
{
	//printf("복호화! 사용중인 대칭키 : %s\n", key);
	int lena;
	char buf[2048];
	unsigned char buf2[2048];
	memcpy(buf, decode64((unsigned char*)contents, 2048), len);
	lena = server.decrypt_block(buf2, (unsigned char*)buf, len, (unsigned char*)key);
	buf2[lena] = 0;

	return (char*)buf2;
}


/*큐의 최상위 메시지를 읽어 헤더를 확인 후 해당 기능으로 분기.
*parameter: 서버 객체
*return: 없음
*/
void process(AuthServer* server)
{
	char userID[ID_LEN];	//유저의 id
	char sym_key[64]; //서버와 공유하는 대칭키

	while (1)
	{
		if (server->isEmpty() == false)
		{
			if (strcmp(server->peekMessage().msg.header, "loginID") == 0) {
				/*
					client로부터 로그인 할 ID를 받음
					유저 파일은 '사용자이름.txt'로 저장되어 있음 -> 파일 이름으로 검색하여 회원 유무 판단
					1) 회원 O -> 사용자의 파일을 읽어 N을 client에게 보냄
					2) 회원 X -> 사용자가 아님을 client에게 보냄
				*/

				//id만 받아서 유저 있는지 검색
				char arg[1][4096];
				//contents안에 있는 id 가져옴

				server->parse_msg(server->peekMessage().msg.contents, 1, arg[0]);


				//유저 저장
				strcpy(userID, arg[0]);
				printf("id : %s\n", userID);

				std::string path = "user\\";
				path += userID;
				path += ".txt";
				if (access(path.c_str(), 0) == 0)	//파일 있음
				{

					printf("유저 찾음\n");
					//파일에서 n 읽기
					char N[CONTENTS_SIZE];	//파일에서 읽어올 N
					FILE* fp;	//파일 포인터
					fp = fopen(path.c_str(), "r");
					fscanf(fp, "%s", N);

					printf("유저 파일의 n값 : %s\n", N);
					fclose(fp);

					//유저 파일에서 n을 보냄
					AuthServer::send_msg(server->peekMessage().sock, "loginN", 1, N);
				}
				else {//id 없음 -> id값을 제목으로 가진 유저 없음

					AuthServer::send_msg(server->peekMessage().sock, "login", 1, "0");
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "login") == 0)
			{
				/*
				사용자가 PW를 보내옴
				-> login 함수를 호출 -> 세션키를 return받아 저장
				*/

				strcpy(sym_key, login(server, (char*)userID));
			}

			else if (strcmp(server->peekMessage().msg.header, "join") == 0) //회원가입 요청 처리
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
				printf("됨");
			}

			else if (strcmp(server->peekMessage().msg.header, "diaryPriv") == 0) //개인 다이어리 선택 시 해당 메뉴로 분기 메시지 전송
			{
				AuthServer::send_msg(server->peekMessage().sock, "diaryPriv", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "writeSha_chk") == 0) //다이어리 공유 대상 존재 여부 확인
			{
				char arg[1][128];
				server->parse_msg(server->peekMessage().msg.contents, 1, arg[0]);
				char path[64];
				sprintf(path, "user\\%s.txt", arg[0]);
				if (access(path, 0) == 0)	//파일 있음
				{
					AuthServer::send_msg(server->peekMessage().sock, "writeSha_chk_rt", 1, "1");
				}
				else {//id 없음 -> id값을 제목으로 가진 유저 없음

					AuthServer::send_msg(server->peekMessage().sock, "writeSha_chk_rt", 1, "0");
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "writePriv") == 0) //클라이언트로부터 수신한 개인 다이어리 복호화 후 암호화해서 저장
			{
				char aa[3][1024];

				server->parse_msg(server->peekMessage().msg.contents, 3, aa[0], aa[1], aa[2]);
				printf("\n<클라이언트가 보낸 암호화된 다이어리 내용>\n%s\n", aa[1]);

				if (strcmp(aa[0], "1") == 0)
					//개인 다이어리 받아와서 파일로 저장
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

					//암호화한거 복호화 해서 result_buf에 넣어줌
					strcpy(result_buf, msg_decrypt(*server, aa[1], atoi(aa[2]), server->peekMessage().sym_key));
					//aa[1] : 암호문, aa[2] : 암호문 길이 -> 이 두 값으로 복호화 함
					printf("\n복호화된 다이어리 내용 : %s\n", result_buf);

					fp = fopen(buf, "w");
					len = publicEncrypt(result_buf, result_buf2);
					//서버 공개키로 다시 암호화
					//printf("테스트 : %d", len);
					sprintf(buf, "%d\n", len);

					fwrite(buf, sizeof(char), strlen((char*)buf), fp);

					fwrite(base64((unsigned char*)result_buf2, 1024, result_len), sizeof(char), strlen((char*)base64((unsigned char*)result_buf2, 1024, result_len)), fp);
					//base64 인코딩 해서 파일에 쓰고 저장

					fclose(fp);

					AuthServer::send_msg(server->peekMessage().sock, "writePrivEnd", 1, "0");

				}
				else if (strcmp(server->peekMessage().msg.contents, "2") == 0)
					AuthServer::send_msg(server->peekMessage().sock, "diaryPriv", 1, "2");

			}

			else if (strcmp(server->peekMessage().msg.header, "writeShared") == 0) // //클라이언트로부터 수신한 공유 다이어리 복호화 후 암호화해서 저장
			{
				char aa[3][1024];

				server->parse_msg(server->peekMessage().msg.contents, 3, aa[0], aa[1], aa[2]);
				printf("\n<클라이언트가 보낸 암호화된 다이어리 내용>\n%s\n", aa[1]);

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

				//암호화한거 복호화 해서 result_buf에 넣어줌
				strcpy(result_buf, msg_decrypt(*server, aa[1], atoi(aa[2]), server->peekMessage().sym_key));
				//aa[1] : 암호문, aa[2] : 암호문 길이 -> 이 두 값으로 복호화 함
				printf("\n복호화된 다이어리 내용 : %s\n", result_buf);

				fp = fopen(buf, "w");
				len = publicEncrypt(result_buf, result_buf2);
				//서버 공개키로 다시 암호화
				//printf("테스트 : %d", len);
				sprintf(buf, "%d\n", len);

				fwrite(buf, sizeof(char), strlen((char*)buf), fp);

				fwrite(base64((unsigned char*)result_buf2, 1024, result_len), sizeof(char), strlen((char*)base64((unsigned char*)result_buf2, 1024, result_len)), fp);
				//base64 인코딩 해서 파일에 쓰고 저장

				fclose(fp);

				AuthServer::send_msg(server->peekMessage().sock, "writeSharedEnd", 1, "0");
			}

			else if (strcmp(server->peekMessage().msg.header, "readAL") == 0) {	//read alone liist
				/*개인 일기 리스트 client에게 보내기*/
			
				readAloneFiles(server, userID);
			}

			else if (strcmp(server->peekMessage().msg.header, "readAF") == 0) {
				/* 혼자쓴 일기 파일을 읽는다
				1. client가 읽어올 파일 index를 보냄 -> 파일 이름 만들어서 파일 open
				  1) 파일 있음 -> 서버의 공개키로 암호화 되어 있는 내용을 개인키로 복호화하여 세션키로 암호화하여 보냄
				  2) 파일 없음 -> 오류 메시지
				  3) 파일 내용 없음 -> 오류 메시지
				*/


				//client가 보낸 번호의 파일을 보냄
				char* indexStr = server->peekMessage().msg.contents;   //번호 읽어옴
				char path[FILE_LEN] = "";   //파일 경로

				//파일 경로 만들기 : 폴더명 + 유저id + "_" + index + ".txt"
				strcpy(path, "private_diary\\");
				strcat(path, userID);
				strcat(path, "_");
				strcat(path, indexStr);
				strcat(path, ".txt");

				printf("%s\n", path);

				//파일이 없음
				if (access(path, 0) != 0) {
					//client가 잘못된 index를 보냄(파일 없음) -> no alone file err
					AuthServer::send_msg(server->peekMessage().sock, "noAFerr", 1, "파일이 존재하지 않습니다.");
				}
				//암호화된 파일을 복호화 하여 읽어옴
				char plainText[BUFFSZ];
				int check = getFileEncrypted(path, plainText);

				if (check == -1) {//파일 열기 실패
					AuthServer::send_msg(server->peekMessage().sock, "noAFerr", 1, "파일이 존재하지 않습니다.");
				}
				else if (check == -2) {//파일 내용 없음
					AuthServer::send_msg(server->peekMessage().sock, "noAFerr", 1, "파일 내용이 없습니다.");
				}
				else {//정상진행
					//암호화 + 인코딩 해서 보냄
					int encyptLen; //암호문의 길이 넣을 변수 만들어주고
					char tmp_buf[3000]; // 암호문 넣을 곳
					char tmp_buf2[32]; //암호문 길이(= encyptLen) 넣을 곳

					strcpy(tmp_buf, msg_encrypt(*server, plainText, encyptLen, server->peekMessage().sym_key)); //암호화해서 tmp_buf에 넣음
					sprintf(tmp_buf2, "%d", encyptLen); //암호문의 길이를 tmp_buf2에 넣어줌
					//매개변수 2개 : 1. 암호문 2. 암호문 길이
					AuthServer::send_msg(server->peekMessage().sock, "readAF", 2, tmp_buf, tmp_buf2);

				}


			}

			else if (strcmp(server->peekMessage().msg.header, "back2priv") == 0)  //개인 다이어리 메누로 돌아가기 선택 시 해당 메뉴로 분기 메시지 전송
			{
				AuthServer::send_msg(server->peekMessage().sock, "back2priv", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "back2main") == 0)  //메인 메뉴로 돌아가기 선택 시 해당 메뉴로 분기 메시지 전송
			{
				AuthServer::send_msg(server->peekMessage().sock, "back2main", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "diaryShared") == 0)  //공유 다이어리 선택 시 해당 메뉴로 분기 메시지 전송
			{
				AuthServer::send_msg(server->peekMessage().sock, "diaryShared", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "readShareList") == 0) {
				/* 두사람이 공유하는 공유일기 파일 리스트 보내기
				- 공유 폴더 이름 : 'shared_diary'
				- 공유 파일 이름 : '사용자1_사용자2_index.txt'
				1. 사용자의 파일 이름이 포함된 txt파일이 존재하는지 알아냄
				  1) 존재 X : 오류메시지
				  2) 존재 O : 파일 명을 하나씩 보냄 -> 다 보내면 파일 보내는 것이 끝났음을 알림
				*/

				_finddata_t fd;	//파일의 정보들을 저장하는 구조체
				long handle;	//파일 검색 결과 값 리턴 -1 : 조건에 맞는 파일 없음, 0 : 파일 있음
				//첫 파일 검색
				char pathSpec[FILE_LEN] = "";
				sprintf(pathSpec, "shared_diary\\*%s*.txt", userID);
				handle = _findfirst(pathSpec, &fd);

				if (handle == -1) {//파일 존재 안함
					AuthServer::send_msg(server->peekMessage().sock, "getShareListErr", 1, "\n작성된 공유 일기가 존재하지 않습니다.");
				}
				else {//파일 있으므로 다른 파일도 검색 해봄
					int count = 0;	//파일 갯수 count
					char countStr[30];	//count를 string으로

					do {
						count++;
						sprintf(countStr, "%d", count);
						printf("%s.%s\n", countStr, fd.name);
						//index, 파일 이름 보내기
						AuthServer::send_msg(server->peekMessage().sock, "shareListIng", 2, countStr, fd.name);
					} while (_findnext(handle, &fd) == 0);
					//파일 리스트 다 보냄 : read shared list end
					AuthServer::send_msg(server->peekMessage().sock, "readSListEnd", 1, "0");
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "readShareFile") == 0) {
				/* 사용자가 원하는 파일을 열어서 보냄
				- 공유 폴더 이름 : 'shared_diary'
				- 공유 파일 이름 : '사용자1_사용자2_index.txt'
				1. 사용자는 파일의 index를 보냄
				2. 사용자 ID로 파일 검색하면서 count하여 사용자가 보낸 index와 같아지면 파일 처리
				  1) 파일 있음 : 서버의 공개키로 암호화된 파일을 개인키로 복호화하여 다시 세션키로 암호화하여 보냄
				  2) 파일 없음 : 오류메시지
				  3) 파일 내용 없음 : 오류메시지
				*/

				_finddata_t fd;	//파일의 정보들을 저장하는 구조체
				long handle;	//파일 검색 결과 값 리턴 -1 : 조건에 맞는 파일 없음, 0 : 파일 있음
				//첫 파일 검색
				char pathSpec[FILE_LEN] = "";	//검색할 spec
				sprintf(pathSpec, "shared_diary\\*%s*.txt", userID);
				handle = _findfirst(pathSpec, &fd);

				if (handle == -1) {//파일 존재 안함
					AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "파일이 존재하지 않습니다.1\n");
				}
				else {//파일 있으므로 다른 파일도 검색 해봄
					int count = 0;	//파일 갯수 count
					char countStr[30];	//count를 string으로

					do {
						count++;
						sprintf(countStr, "%d", count);
						printf("%s.%s\n", countStr, fd.name);
						if (strcmp(countStr, server->peekMessage().msg.contents) == 0) {
							//보낸 인덱스번째 파일 처리
							//암호화된 파일을 복호화 하여 읽어옴
							char plainText[BUFFSZ];
							char path[BUFFSZ];	//파일 경로
							strcpy(path, "shared_diary\\");
							strcat(path, fd.name);
							int check = getFileEncrypted(path, plainText);

							if (check == -1) {//파일 열기 실패
								AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "파일이 존재하지 않습니다.2");
								break;
							}
							else if (check == -2) {//파일 내용 없음
								AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "파일 내용이 없습니다.");
								break;
							}
							else {//정상진행
							   //암호화 + 인코딩 해서 보냄
								int encyptLen; //암호문의 길이 넣을 변수
								char tmp_buf[3000]; // 암호문 넣을 곳
								char tmp_buf2[32]; //암호문 길이(= encyptLen) 넣을 곳

								strcpy(tmp_buf, msg_encrypt(*server, plainText, encyptLen, server->peekMessage().sym_key)); //암호화해서 tmp_buf에 넣음
								sprintf(tmp_buf2, "%d", encyptLen); //암호문의 길이를 tmp_buf2에 넣어줌

								//read shared file end -> 매개변수 2개 : 1. 암호문 2. 암호문 길이
								AuthServer::send_msg(server->peekMessage().sock, "readSFileEnd", 2, tmp_buf, tmp_buf2);
								break;
							}
						}
					} while (_findnext(handle, &fd) == 0);

					if (count < atoi(server->peekMessage().msg.contents)) {
						//client가 보낸 index가 파일의 최고 index보다 큼 -> get shared file err
						AuthServer::send_msg(server->peekMessage().sock, "getShareFileErr", 1, "파일이 존재하지 않습니다.3");
					}
				}
			}

			else if (strcmp(server->peekMessage().msg.header, "back2shrd") == 0)  //공유 다이어리로 돌아가기 선택 시 해당 메뉴로 분기 메시지 전송
			{
				AuthServer::send_msg(server->peekMessage().sock, "back2shrd", 1, "1");
			}

			else if (strcmp(server->peekMessage().msg.header, "logout") == 0) { //로그아웃
				//strcpy(sym_key, "0");
				AuthServer::send_msg(server->peekMessage().sock, "logout", 1, "0");
			}

			server->popMessage();
		}
	}
}



/*
혼자쓰기 파일의 제목 리스트 client에게 보내기
- 혼자쓰기 하는 폴더 이름 : 'private_diary'
- 혼자쓰기 하면 생기는 파일 이름 : 사용자이름_index.txt
1. 사용자ID가 들어간 txt파일의 갯수를 count
  1) 0개 -> 파일 없음 -> 오류 메시지 송신
  2) n개 -> 다시 파일 존재하는지 검사하며 파일 이름 보냄 -> 파일 다 보내는 것이 끝났음을 알림
*/
void readAloneFiles(AuthServer* server, char* userID) {
	//파일 경로 1~... 만들어서 다음에 쓸 index구하기
	char path[FILE_LEN];   //파일 위치
	int index = 0;   //들어있는 파일 갯수 count
	char indexStr[10] = "";   // index 정수 값을 문자열로

	index = countFiles(userID, "private_diary\\");

	printf("\n찾은 파일의 개수 : %d\n", index);

	if (index == 0) {//index = 0 : 파일 리스트 없음
	   //없기 때문에 "작성된 일기가 없습니다." 메시지를 준다. -> 그리고 이전의 혼자쓰기 메뉴로 돌아감
		AuthServer::send_msg(server->peekMessage().sock, "noAL", 1, "작성된 일기가 없습니다.\n");   //there is no Alone List
	}
	else {//파일이 1개 이상 있다
	   //파일 이름 하나하나 전부 보냄
		for (int i = 0; i < index; i++) {
			//파일 이름 생성
			strcpy(path, "");   //초기화
			//유저id + "_index" + ".txt"
			strcpy(path, userID);   //유저 id
			strcat(path, "_");

			strcpy(indexStr, "");   //index string초기화
			sprintf(indexStr, "%d", i + 1);   //정수를 배열로 바꿈

			strcat(path, indexStr);   //index
			strcat(path, ".txt");   //.txt

			//printf("%s\n", path);

			//alone list reading(계속 보내는 중) -> 파일 계속 보내는 중임 -> client에서는 받아서 출력만 함
			// (index + 파일이름) 보냄
			AuthServer::send_msg(server->peekMessage().sock, "ALing", 2, (const char*)indexStr, (const char*)path);
		}
		//파일 이름 보내는 것이 끝낸것을 알림 -> 읽을지 말지 메뉴로 넘어감
		AuthServer::send_msg(server->peekMessage().sock, "ALend", 1, "0");
	}
}


/* 파일 개수 count해서 보냄
사용자ID + index값으로 파일 이름 만들어 갯수를 count해서 보냄
*/
int countFiles(char* userID, const char* folderName) {
	char indexStr[10] = "";
	char path[FILE_LEN];
	int count = 0;

	do {
		strcpy(path, "");   //초기화
		//폴더이름 + 유저id + "_index" + ".txt"
		strcpy(path, folderName);   //폴더
		strcat(path, userID);   //유저 id
		strcat(path, "_");

		strcpy(indexStr, "");   //index string초기화
		sprintf(indexStr, "%d", count + 1);

		strcat(path, indexStr);   //index
		strcat(path, ".txt");   //.txt
		count++;      //count증가
	} while (access(path, 0) == 0);

	return count - 1;
	//파일이 없으면 count = 1이지만 갯수를 보내기 위해 -1 해줌
	//0 : 잘 처리됨, -1 : 파일 열기 실패, -2 : 파일 내용이 없습니다.
}


// 서버의 공개키로 암호화된 txt파일을 읽어와서 디코딩+복호화 = 평문
int getFileEncrypted(char* path, char* plainText) {
	int len;
	char result_buf[4096];
	//char result[4096] = "";
	char ch;
	char* p = result_buf;
	FILE* fp;

	fp = fopen(path, "r");
	if (fp == NULL) {	//파일 open 실패
		printf("파일 열기 실패\n");
		return -1;
	}

	fscanf(fp, "%s", result_buf);
	if (strlen(result_buf) < 0) {	//파일 내용이 존재하지 않음
		printf("파일 내용이 없음\n");
		return -2;
	}

	len = atoi(result_buf);
	printf("\n<서버 폴더에 있는 사용자의 암호화된 다이어리 내용>\n");
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

	printf("\n서버 폴더에서 사용자의 파일 복호화 : %s\n", plainText);

	return 0;	//정상 종료
}