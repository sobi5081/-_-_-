#include "authserver.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcryptoMD.lib")
#pragma comment(lib, "libsslMD.lib")

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define TIMESKEW 2
#define RSA_ALGORITHM_H

/*DES 암호화 함수
*parameter: 암호화된 메시지가 저장 될 변수, 평문 메시지, 평문 메시지 길이, 대칭키값
*return: 암호화된 메시지 길이
*/
//깃허브 소스코드 인용
int AuthServer::encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	int addLen = 0, orgLen = 0;
	unsigned long err = 0;

	ERR_load_crypto_strings();
	EVP_CIPHER_CTX_init(ctx);
	if (EVP_EncryptInit(ctx, EVP_des_cfb8(), key, NULL) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_EncryptInit() - %s\n", ERR_error_string(err, NULL));
		return -1;
	}
	if (EVP_EncryptUpdate(ctx, cipherText, &orgLen, plainText, plainTextLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_EncryptUpdate() - %s\n", ERR_error_string(err, NULL));

		return -1;
	}

	if (EVP_EncryptFinal(ctx, cipherText + orgLen, &addLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_EncryptFinal() - %s\n", ERR_error_string(err, NULL));
		return -1;
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	ERR_free_strings();
	return addLen + orgLen;
}


/*DES 복호화 함수
*parameter: 복호화된 메시지가 저장 될 변수, 암호화된 메시지 본문, 암호화된 메시지 본문 길이, 대칭키값
*return: 복화화된 메시지 길이
*/
//깃허브 소스코드 인용
int AuthServer::decrypt_block(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	unsigned long err = 0;
	int toLen = 0, outLen = 0;
	int ret = 0;

	ERR_load_crypto_strings();
	EVP_CIPHER_CTX_init(ctx);

	if (EVP_DecryptInit(ctx, EVP_des_cfb8(), key, NULL) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_DecryptInit() - %s\n", ERR_error_string(err, NULL));
		
		return -1;
	}
	if (EVP_DecryptUpdate(ctx, plainText, &toLen, cipherText, cipherTextLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_DecryptUpdate() - %s\n", ERR_error_string(err, NULL));

		return -1;
	}

	if (EVP_DecryptFinal(ctx, &plainText[cipherTextLen], &outLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_DecryptFinal() - %s\n", ERR_error_string(err, NULL));

		return -1;
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	ERR_free_strings();

	return toLen + outLen;
}


/*클라이언트로부터 수신된 메시지가 저장될 메시지 큐
수신된 메시지는 구조체로 변환되고 해당 큐에 삽인된다.
*parameter: 없음.
*return: 없음.
*/
std::queue<MSG_QUEUE> AuthServer::msg_list; // 클래스 static 변수 초기화
											//서버 열기 


/*서버 객체 생성자. 해당 포트로 서버를 가동.
*parameter: 서버 포트
*return: 없음
*/
AuthServer::AuthServer(int port) 
{
	keypair = NULL;
	private_key = NULL;
	public_key = NULL;
	encrypt = NULL;
	decrypt = NULL;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	hServSock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&servAdr, 0, sizeof(servAdr));
	servAdr.sin_family = AF_INET;
	servAdr.sin_addr.s_addr = htonl(INADDR_ANY);

	servAdr.sin_port = htons(port);

	bind(hServSock, (SOCKADDR*)& servAdr, sizeof(servAdr));

	listen(hServSock, 5);
}


/*서버 객체 소멸자. 사용한 자원을 해제한다.
*parameter: 없음
*return: 없음
*/
AuthServer::~AuthServer() {
	RSA_free(keypair);
	if (private_key != 0) RSA_free(private_key);
	if (public_key != 0) RSA_free(public_key);
	if (encrypt != 0) free(encrypt);
	if (decrypt != 0) free(decrypt);
	closesocket(hServSock);
	WSACleanup();
}


/*클라이언트 소켓 연결 대기. 사용자가 연결 요청 시 accept를 통하여 연결 수락.
*parameter: 없음
*return: 없음
*/
void AuthServer::wait()
{
	int cIntAdrSize = 0;
	cIntAdrSize = (int)sizeof(cIntAdr);//클라이언트 정보 들어있는 구조체의 크기 (밑에서 소켓 생성할때 구조체 크기만큼 생성해야돼서)
	std::thread *th;
	while (1) { //무한루프 돌면서 접속 확인
		hCintSock = accept(hServSock, (SOCKADDR*)& cIntAdr, &cIntAdrSize); //누가들어오면
		printf("수락!\n");
		th = new std::thread(AuthServer::clientThread, hCintSock); //쓰레드생성
	}
}


/*패킷 메시지의 공백 문자 '#'을 제거
*parameter: 메시지 본문
*return: 없음
*/
void split(char *buf) 
{
	char *msg = buf;
	for (int i = 0; i < 4096; i++)
	{
		if (msg[i] == '#') {
			msg[i] = 0;
			break;
		}
	}

}


/*메시지 본문에서 ','를 기준으로 메시지를 분리
*parameter: 메시지 본문, 분리될 메시지 개수, 각 메시지가 삽입될 문자열 변수들(가변인자).
*return: 없음
*/
void AuthServer::parse_msg(const char* msg, int Count, ...)
{
	char* buf = NULL;
	//-----가변인자
	va_list Marker;
	va_start(Marker, Count);
	buf = strtok((char*)msg, ",");
	for (int i = 0; i < Count; i++) {
		strcpy(va_arg(Marker, char*),buf);

		if ( i != Count-1) buf = strtok(NULL, ",");
	}
	va_end(Marker);
	//-----가변인자 끝
}


/*해당 클라이언트로 메시지를 전송. 가변인자를 통하여 여러 내용을 포함.
*parameter: 클라이언트 소켓, 메시지 헤더, 메시지 내용 개수, 각 메시지 내용
*return: 없음
*/
void AuthServer::send_msg(SOCKET sock, const char* header, int Count, ...)
{
	SOCK_MSG msg;
	std::string buf = "";
	char header_[16];
	char contents_[4096];
	strcpy(header_, header);

	//-----가변인자
	va_list Marker;
	va_start(Marker, Count);

	for (int i = 0; i < Count; i++) {
		buf += va_arg(Marker, char*);
		if (i != Count - 1) buf += ",";
	}
	va_end(Marker);
	//-----가변인자 끝

	strcpy(contents_, buf.c_str());
	for (int i = strlen(header_); i < 16; i++)
		header_[i] = '#'; //문자열의 마지막에 # 넣어줌
	for (int i = buf.size(); i < 4096; i++)
		contents_[i] = '#'; //문자열의 마지막에 # 넣어줌

	strncpy(msg.header, header_, 16);
	strncpy(msg.contents, contents_, 4096);
	send(sock, (char*)& msg, sizeof(SOCK_MSG), 0);

}


/*지정된 길이의 메시지를 전달받아 공백문자를 처리하여 메시지큐에 삽입.
*parameter: 클라이언트 소켓, 메시지, 대칭키값
*return: 없음
*/
void AuthServer::process_msg(SOCKET sock, std::string msg, std::string &sym_key)
{
	SOCK_MSG*message = (SOCK_MSG*)msg.c_str(); //string을 char로 바꿔서 구조체로 만들어줌
	//printf("%s 1111 %s\n", msg);

	split(message->header); //헤더랑 컨텐츠의 첫 #을 널문자로 바꿔줌
	split(message->contents);

	MSG_QUEUE msg_queue; 
	SOCK_MSG sock_msg; 
	msg_queue.sock = sock; //큐내용에 소켓을 넣어줌
	strcpy(sock_msg.header,message->header); //수신된 헤더를 큐내용에 넣을 sock_msg의 헤더에 넣어줌
	strcpy(sock_msg.contents, message->contents); //컨텐츠도 마찬가지
	msg_queue.msg = sock_msg; //다 만든 sock_msg를 큐내용의 msg에 넣어줌
	if (strcmp(sock_msg.header, "login") == 0) {
		char arg[3][4096];
		char final_buf[128];

		parse_msg(message->contents, 3, arg[0], arg[1], arg[2]);
		privateDecrypt(atoi(arg[1]), decode64((unsigned char*)arg[2], 2048), final_buf);
		sym_key = final_buf;


	}
	strcpy(msg_queue.sym_key, sym_key.c_str());
	msg_list.push(msg_queue); //다 만든 큐내용을 큐에 넣어줌
}


/*큐가 비었는지 확인
*parameter: 없음
*return: 없음
*/
bool AuthServer::isEmpty() 
{
	return (AuthServer::msg_list.size() == 0); //큐의 사이즈가 0이면 1
}


/*큐의 최상위 메시지 반환
*parameter: 없음
*return: 큐의 최상의 메시지
*/
MSG_QUEUE& AuthServer::peekMessage() 
{
	return AuthServer::msg_list.front(); //큐에서 맨 먼저 온 메시지를 반환 
}


/*큐의 최상위 메시지를 삭제
*parameter: 없음
*return: 없음
*/
void AuthServer::popMessage()
{
	if (AuthServer::msg_list.size() != 0) 
	{
		AuthServer::msg_list.pop(); //메시지 뺌
	}
}


/*각 클라이언트의 메시지를 수신, 처리하는 함수
*parameter: 클라이언트 소켓
*return: 없음
*/
void AuthServer::clientThread(SOCKET sock) //소비:클라이언트인증+수신된메시지를 proces_msg에 넣어줌
{
	printf("연결완료!\n");
	send_msg(sock, "success", 1, "1"); //클라이언트가 sucess 받으면 로그인 화면 띄워줘야하니깐
	char buf[8192];
	std::string msg_buf = "";
	msg_buf.clear();
	int recv_len = sizeof(SOCK_MSG);
	int len = 0;
	std::string sym_key="";
	while (1)
	{
		len = recv(sock,  buf, recv_len, 0); //원래 받기로 한 길이는 recv_len인데 실제 받은거를 buf에 넣고 실제 받은 길이를 반환
		if (len == -1)
			break;
		buf[len] = 0; //0이 문자열의 끝을 알려줌

		recv_len -= len; //원래 받으려던 길이에서 실제 받은 길이를 뺌 -> 원래 받으려던 길이만큼 다 받을때까지 빼는거
		msg_buf += buf;
		if (recv_len == 0) //목적하던 길이의 메시지를 다 수신할 경우
		{
			process_msg(sock, msg_buf, sym_key); //메시지를 구조체로 만들어주는 함수로 보내줌

			msg_buf.clear(); //메시지 버퍼는 다시 비워줌
			recv_len = sizeof(SOCK_MSG); //수신할 메시지 길이를 원래 받을 길이만큼 초기화
		}
	}
	printf("사용자 종료!\n");
	closesocket(sock);
}