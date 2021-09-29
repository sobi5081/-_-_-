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


/*메인함수. 클라이언트 객체 생성 및 서버와 연결 후 메시지 수신 대기.
*parameter: 없음
*return: 종료 코드
*/
int main()
{
	AuthClient client("127.0.0.1", 50000);
	client.recv_msg(process_msg);

	return 0;
}


/*
*로그인 성공시 메인메뉴를 출력. 해당 메뉴 번호 입력 시 해당 기능으로 분기.
*parameter: 클라이언트 객체
*return: 없음
*/
void main_menu(AuthClient& client)
{
	printf("\n-----------------------\n");
	printf("< 메인 메뉴 >\n");
	printf("-----------------------\n");
	printf("1. 개인 다이어리\n");
	printf("2. 공유 다이어리\n");
	printf("3. 로그아웃\n");
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
*개인다이어리 접근시 개인다이어리 메뉴를 출력. 해당 메뉴 번호 입력 시 해당 기능으로 분기.
*parameter: 클라이언트 객체
*return: 없음
*/
void Priv_diary(AuthClient& client)
{
	printf("\n-----------------------\n");
	printf("< 개인 다이어리 >\n");
	printf("-----------------------\n");
	printf("1. 쓰기\n");
	printf("2. 목록\n");
	printf("3. 뒤로가기\n");
	printf("-----------------------\n");
	int n;
	printf(">> ");
	scanf("%d", &n);
	switch (n) {
	case 1:
		write(client, 1);
		break;


	case 2:
		//목록 - 혼자 쓴 일기 목록 받기 위한 소켓 전송
		printf("\n-----------------------\n");
		printf("개인 다이어리 목록\n");
		printf("-----------------------\n");
		client.send_msg("readAL", 1, "0");	//readAL: read alone list
		break;

	case 3:
		client.send_msg("back2main", 1, "0");
		return;

	}
}


/*공유다이어리 접근시 공유다이어리 메뉴를 출력. 해당 메뉴 번호 입력 시 해당 기능으로 분기.
*parameter: 클라이언트 객체
*return: 없음
*/
void shared_diary(AuthClient& client) {
	printf("\n-----------------------\n");
	printf("< 공유 다이어리 >\n");
	printf("-----------------------\n");
	printf("1. 쓰기\n");
	printf("2. 목록\n");
	printf("3. 뒤로가기\n");
	printf("-----------------------\n");

	int cmd;
	printf(">> ");
	scanf("%d", &cmd);
	switch (cmd) {
	case 1:
		//쓰기 - 같이 쓰기
		write(client, 2);
		break;

	case 2:
		//목록 - 같이 쓴 일기 목록 받아오기위한 소켓 전송
		client.send_msg("readShareList", 1, "0");   //readSL : read share list
		break;

	case 3:
		client.send_msg("back2main", 1, "0");
		return;
	}
}


/*최초 접속 화면 출력. 해당 메뉴 번호 입력 시 해당 기능으로 분기.
*parameter: 클라이언트 객체
*return: 없음
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
	printf("1.로그인\n");
	printf("2.회원가입\n");
	printf("3.종료\n");
	printf("-----------------------\n");
	printf(">> ");
	scanf("%d", &cmd);
	std::string buf = "";

	char encrypt_buf[1024];
	char mdString[SHA_DIGEST_LENGTH * 2 + 1];

	switch (cmd)
	{
	case 1:	//로그인

		printf("\n아이디를 입력하세요 : ");
		scanf("%s", id);




		//hasing((char*)pw, (char*)hash_pw, 100);

		//client.send_msg("loginID", 2, id,"filling");
		client.send_msg("loginID", 1, id);
		break;

	case 2: //회원가입
		printf("아이디를 입력하세요 : ");
		scanf("%s", id);
		printf("비밀번호를 입력하세요 : ");
		scanf("%s", pw);



		//입력받은 패스워드 100번 해시
		hasing((char*)pw, (char*)hash_pw, 100);
		//id, 이름, 해시100번 한 비밀번호, 암호화한 대칭키 보냄  //대칭키 안보냄
		client.send_msg("join", 2, id, hash_pw);


		break;

	case 3:	//exit(0);
		exit(0);
	}
}


/*작성한 다이어리 내용을 서버와의 대칭키로 암호화한 후, Base64인코딩.
*parameter: 클라이언트 객체, 암호화할 내용, 암호문의 길이, 서버와의 대칭키
*return: base64 인코딩 된 문자열
*/
char* msg_encrypt(AuthClient& client, const char* contents, int& len, char* key) //암호문의 길이도 알아둬야 함
{
	//printf("암호화! 사용중인 대칭키 : %s\n", key);
	int lena;
	unsigned char buf[2048];
	memset(buf, 0, 2048);
	lena = client.encrypt_block(buf, (unsigned char*)contents, strlen((char*)contents), (unsigned char*)key);
	buf[lena] = 0;

	len = lena;

	return base64((unsigned char*)buf, 2048, lena);
}


/*서버로부터 받은 base64 인코딩 된 다이어리 내용을 디코딩 한 후, 서버와의 대칭키로 복호화.
*parameter: 클라이언트 객체, base64된 내용
*return: 복호화된 문자열
*/
char* msg_decrypt(AuthClient& client, const char* contents, int len, char* key) //암호화 된 길이 넣어줘야 함
{
	//printf("복호화! 사용중인 대칭키 : %s\n", key);
	int lena;
	char buf[2048];
	unsigned char buf2[2048];
	//printf("BASE64 :: %s\n", decode64((unsigned char*)contents, 2048));
	memcpy(buf, decode64((unsigned char*)contents, 2048), len); //메모리카피
	
	lena = client.decrypt_block(buf2, (unsigned char*)buf, len, (unsigned char*)key);
	buf2[lena] = 0;
	return (char*)buf2;

}


/*
*다이어리 작성 후, 암호화와 base64 인코딩 한 후, 서버로 전송.
*parameter: 클라이언트 객체, 개인/공유 다이어리 구분값
*return: 없음
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
	case 1:	//개인 다이어리 쓰기
	{
		printf("내용을 입력하세요. 작성이 끝나면 [Ctrl+Q]를 눌러주세요. \n");
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
		wprintf(L"\n내용 : \n%ls\n", buf);
		//ConvertWCtoC(buf);
		int len; //암호문의 길이 넣을 변수 만들어주고
		char tmp_buf[3000]; // 암호문 넣을 곳
		char tmp_buf2[32]; //암호문 길이 넣을 곳

		strcpy(tmp_buf, msg_encrypt(client, ConvertWCtoC(buf), len, client.sym_key)); //암호화해서 tmp_buf에 넣음
		sprintf(tmp_buf2, "%d", len); //암호문의 길이를 tmp_buf2에 넣어줌
		client.send_msg("writePriv", 3, "1", tmp_buf, tmp_buf2);
		//3:매개변수3개, 1 : 개인 다이어리, 마지막 두개가 암호문, 암호문의 길이 --> 이렇게 보내야 함

		break;
	}
	case 2:	//공유 다이어리 쓰기 - 상대방 아이디 체크
	{
		printf("공유할 상대방 아이디를 입력하시오 : \n");
		scanf("%s", partner);
		client.send_msg("writeSha_chk", 1, partner);

		break;
	}
	case 3:	//공유 다이어리 쓰기 - 상대방 아이디 존재할 때 작성
	{
		printf("내용을 입력하세요. 작성이 끝나면 [Ctrl+Q]를 눌러주세요. \n");
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
		wprintf(L"\n내용 : \n%ls\n", buf);
		//ConvertWCtoC(buf);
		int len; //암호문의 길이 넣을 변수 만들어주고
		char tmp_buf[3000]; // 암호문 넣을 곳
		char tmp_buf2[32]; //암호문 길이 넣을 곳

		strcpy(tmp_buf, msg_encrypt(client, ConvertWCtoC(buf), len, client.sym_key)); //암호화해서 tmp_buf에 넣음
		sprintf(tmp_buf2, "%d", len); //암호문의 길이를 tmp_buf2에 넣어줌
		client.send_msg("writeShared", 3, partner, tmp_buf, tmp_buf2);
		//3:매개변수3개, 1 : 개인 다이어리, 마지막 두개가 암호문, 암호문의 길이 --> 이렇게 보내야 함

		break;
	}
	default:
		break;
	}


}


/*구조체로 변환된 메시지를 받으면 소켓의 헤더에 해당하는 기능으로 분기.
*parameter: 소켓 구조체, 클라이언트 객체
*return: 없음
*/
void process_msg(SOCK_MSG& message, AuthClient& client)
{
	if (strcmp(message.header, "success") == 0) //서버 - 클라이언트 접속 성공
	{
		init(client);
	}
	else if (strcmp(message.header, "loginN") == 0) {	//로그인1
		/* 서버로부터 N을 받아옴
		1. 세션키 생성 -> 서버의 공개키로 암호화
		2. n-1번 해싱
		3. 암호화 길이, n-1번 해시한 값, 암호문(세션키) 보냄
		*/
														
		//유저를 찾아서 N을 받음
		int n = atoi(message.contents);
		//printf("n : %d\n", n);//임시 출력

		int random=0;
		char sym_key[32];
		
		int public_len;
		char encrypt_buf[2048];
		char encrypt_buf_len[32];
		int base_64_len;
		srand(time(NULL));
		while (random < 1000) {
			random = rand() % 5000; //대칭키로 쓸 난수 생성
		}
		
		//printf("대칭키값 : %d\n", random);
		sprintf(sym_key, "%d", random);
	

		strcpy(client.sym_key, sym_key);

		public_len = publicEncrypt((char*)sym_key, encrypt_buf);

		sprintf(encrypt_buf_len, "%d", public_len);

		char pw[32];
		printf("비밀번호를 입력하세요 : ");
		scanf("%s", pw);
		//n-1 해시한 값을 보냄
		char hash_pw[SHA_DIGEST_LENGTH * 2 + 1];	//비밀번호 해시 담을 변수
		hasing((char*)pw, (char*)hash_pw, n - 1);	//n-1번 해싱
		client.send_msg("login", 3, (const char*)hash_pw, encrypt_buf_len, base64((unsigned char*)encrypt_buf, 2048, base_64_len));
	}

	else if (strcmp(message.header, "login") == 0)	//로그인2
	{
		if (strcmp(message.contents, "1") == 0)	//로그인 성공
		{
			printf("\n* 로그인 성공! *\n");
			main_menu(client);	//로그인 한 상태에서 보이는 메뉴
		}
		else if (strcmp(message.contents, "0") == 0)	//아이디가 틀린 경우
		{
			printf("\n* 해당 사용자를 찾을 수 없습니다 *\n");
			init(client);
		}
		else if (strcmp(message.contents, "2") == 0)	//비밀번호가 틀린 경우
		{
			printf("\n* 비밀번호가 틀렸습니다 *\n");
			init(client);
		}
	}

	else if (strcmp(message.header, "joinEnd") == 0) {	//회원가입 완료
		printf("\n* 회원가입이 완료되었습니다 *\n");
		init(client);
	}

	else if (strcmp(message.header, "diaryPriv") == 0) //개인다이어리 메뉴 함수로 분기
	{
		Priv_diary(client);
	}
	else if (strcmp(message.header, "writePrivEnd") == 0) {	//개인 다이어리 작성 완료
		printf("\n\n* 다이어리 작성이 완료되었습니다 *\n");
		Priv_diary(client);
	}
	else if (strcmp(message.header, "writeSha_chk_rt") == 0) {	//다이어리를 공유할 사용자가 존재여부 ( 0: 존재, 1: 미존재 )
		if (strcmp(message.contents, "1") == 0)
		{
			write(client, 3);
		}
		else
		{
			printf("상대방이 존재하지 않습니다.\n");
			shared_diary(client);
		}
	}

	else if (strcmp(message.header, "writeSharedEnd") == 0) {	//공유 다이어리 작성 완료
		printf("\n\n* 다이어리 작성이 완료되었습니다 *\n");
		shared_diary(client);
	}

	else if (strcmp(message.header, "noAL") == 0) {		//no alone list : 혼자쓰기에서 쓴 일기가 없음
		//aloneMenue 혼자 쓰는 메뉴로 가기
		printf("%s\n", message.contents);
		Priv_diary(client);
	}

	else if (strcmp(message.header, "ALing") == 0) {
		//파일 이름을 받는 중 -> index와 파일 이름 잘라서 출력
		char arg[2][4096];	//자른 배열 저장
		client.parse_msg((const char*)message.contents, 2, arg[0], arg[1]);	//자르기
		printf("%s. %s\n", arg[0], arg[1]);
	}

	else if (strcmp(message.header, "ALend") == 0) {
		//목록 출력 끝 -> 혼자 읽기 -> 읽기 메뉴 출력
		aloneReadMenue(client);
	}

	else if (strcmp(message.header, "noAFerr") == 0) {
		//파일 없음, 파일 내용이 없음 err 출력
		printf("%s\n", message.contents);
		aloneReadMenue(client);
	}

	else if (strcmp(message.header, "readAF") == 0) {
		/* 서버가 보낸 파일 내용을 읽음
		1. 세션키로 암호화된 일기 내용을 복호화
		2. 출력
		3. wait -> 이전 개인 다이어리 메뉴로 돌아감
		*/

		//printf("%s\n", message.contents);
	    //constents : 1. 암호문 2. 암호화된 txt의 길이(복호화에 쓰임)
		char arg[2][5000];   //자른 배열 저장
		//자르기 : arg[0] : 암호문, arg[1] : 암호화된 txt길이
		client.parse_msg(message.contents, 2, arg[0], arg[1]);
	
		char buffer[4096];   //암호화문 복호화한 값을 넣는 버퍼

		strcpy(buffer, msg_decrypt(client, arg[0], atoi(arg[1]), client.sym_key));

		printf("-----------------------------------------------------------\n");
		printf("%s\n", buffer);
		printf("-----------------------------------------------------------\n");
		printf("이전으로 돌아가시려면 아무키를 눌러주세요.\n");

		while (1) {
			if (kbhit()) {
				getch();
				break;
			}
		}
		Priv_diary(client);
	}

	else if (strcmp(message.header, "back2priv") == 0)  //개인다이어리 메뉴로 돌아가기
	{
		Priv_diary(client);
	}

	else if (strcmp(message.header, "diaryShared") == 0) //공유다이어리 메뉴로 분기
	{
	shared_diary(client);
	}

	else if (strcmp(message.header, "back2shrd") == 0)  //공유다이어리 메뉴로 돌아가기
	{
		shared_diary(client);
	}

	else if (strcmp(message.header, "getShareListErr") == 0) {
		//공유된 다이어리 리스트 출력에 관한 에러 출력
	
		printf("%s\n", message.contents);
		shared_diary(client);
	}

	else if (strcmp(message.header, "shareListIng") == 0) {
		/*	공유 다이어리의 리스트 출력 - 출력하는 중	*/

		char arg[2][4096];	//잘라온 내용들
		//arg[0] : index, arg[1] : 파일 이름
		client.parse_msg(message.contents, 2, arg[0], arg[1]);
		printf("%s. %s\n", arg[0], arg[1]);
	}
	else if (strcmp(message.header, "readSListEnd") == 0) {
		sharedReadMenue(client);
	}

	else if (strcmp(message.header, "getShareFileErr") == 0) {
		/*	공유 다이어리 읽기 에러	메시지 출력
		-> 공유 다이어리 메뉴로 돌아감
		*/
		
		printf("%s\n", message.contents);	//에러 메시지 출력
		shared_diary(client);	//공유 다이어리 메뉴로 돌아감
	}

	else if (strcmp(message.header, "readSFileEnd") == 0) {
		/* 서버가 보낸 파일 내용을 읽음
		1. 세션키로 암호화된 일기 내용을 복호화
		2. 출력
		3. wait -> 이전 공유 다이어리 메뉴로 돌아감
		*/
		
		char arg[2][4096];   //자른 배열 저장
		//자르기 : arg[0] : 암호문, arg[1] : 암호화된 txt길이
		client.parse_msg(message.contents, 2, arg[0], arg[1]);

		char buffer[4096];   //암호화문 복호화한 값을 넣는 버퍼

		strcpy(buffer, msg_decrypt(client, arg[0], atoi(arg[1]), client.sym_key));

		printf("-----------------------------------------------------------\n");
		printf("%s\n", buffer);
		printf("-----------------------------------------------------------\n");
		printf("이전으로 돌아가시려면 아무키를 눌러주세요.\n");

		while (1) {
			if (kbhit()) {
				getch();
				break;
			}
		}
		shared_diary(client);
	}

	else if (strcmp(message.header, "back2main") == 0)	//메인으로 돌아가기
	{
	main_menu(client);
	}

	else if (strcmp(message.header, "logout") == 0) //로그아웃 성공
	{
		printf("\n* 로그아웃 성공! *\n");
		init(client);
	}
}


/* 개인 다이어리 읽기 메뉴 1. 읽기 2. 뒤로가기
1. 읽을 파일 번호를 입력 받음 -> 파일 번호를 서버에게 전송
2. 뒤로가기 -> 개인 다이어리 메뉴로 돌아감
*/
void aloneReadMenue(AuthClient& client) {
	printf("-----------------------\n");
	printf("1. 읽기\n");
	printf("2. 뒤로가기\n");
	printf("-----------------------\n");

	int cmd;
	printf(">> ");
	scanf("%d", &cmd);

	switch (cmd)
	{
	case 1:
		printf("읽을 파일 번호를 입력해주세요 : ");
		int number;
		char numberStr[20];
		scanf("%d", &number);
		sprintf(numberStr, "%d", number);
		//번호 보내기
		client.send_msg("readAF", 1, (const char*)numberStr);
		break;
	case 2:
		client.send_msg("back2priv", 1, "0");
		break;
	}
}

/* 공유 다이어리 읽기 메뉴 1. 읽기 2. 뒤로가기
1. 읽을 파일 번호를 입력 받음 -> 파일 번호를 서버에게 전송
2. 뒤로가기 -> 공유 다이어리 메뉴로 돌아감
*/
void sharedReadMenue(AuthClient& client) {
	printf("-----------------------\n");
	printf("1. 읽기\n");
	printf("2. 뒤로가기\n");
	printf("-----------------------\n");

	int cmd;
	printf(">> ");
	scanf("%d", &cmd);

	switch (cmd)
	{
	case 1:
		printf("읽을 파일 번호를 입력해주세요 : ");
		int number;
		char numberStr[20];
		scanf("%d", &number);
		sprintf(numberStr, "%d", number);
		//번호 보내기
		client.send_msg("readShareFile", 1, (const char*)numberStr);
		break;
	case 2:
		client.send_msg("back2shrd", 1, "0");
		break;
	}
}