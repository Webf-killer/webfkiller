# webfkiller
웹 페이지의 보안 취약점을 효과적으로 탐지하는 도구. 프록시 서버를 통해 데이터를 수집하고, 페이로드가 포함된 패킷을 보내서 취약점을 스캔하여 DB에 저장한다.

## 👯‍♀️ Member
- 김서율, 강경서, 구가경, 김수민, 김민지, 강혜인, 김우종

## 🎯 기능
1. **Proxy_mitmproxy.py** : 프록시 서버를 통해 웹 페이지의 요청 및 응답 내용을 수집
2. **Scanner.py** : SQLi, Stored XSS, Reflected XSS, Dom-based XSS 취약점을 탐지
3. **Composer_packet_generator.py** : 페이로드를 이용한 패킷을 생성하고 요청 보냄
4. **DB_util.py** : 결과를 MySQL 데이터베이스에 저장
5. **Payloads.txt** : 취약점 탐지를 위한 다양한 페이로드들.

## ⭐설치 요구사항
- 필요한 파이썬 패키지 설치
```python
pip install selenium requests pymysql mitmproxy webdriver_manager psutil keyboard beautifulsoup4 binascii
```
- 인증서 추가하기
#### 인증서 추가 방법 WIN
1. %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer 실행 (안나오면 프록시랑 스크립트 실행시켜보고 재부팅)
2. 인증서 설치 -> 로컬 컴퓨터 -> 모든인증서를 다음 저장소에 저장
3. 신뢰할 수 있는 루트 인증 기관 -> 마침

#### 인증서 추가 방법 MAC
1. 프록시 실행시킨 상태로  http://mitm.it/ 접속
2. 애플클릭하고 설치 또는
```
sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain $HOME/.mitmproxy/mitmproxy-ca-cert.pem
```
3. command + space누르고 키체인 검색
4. mitmproxy 인증서 더블클릭 후 상단의 신뢰 클릭
5. 이 인증서 사용시: 시스템초기설정사용 -> 항상신뢰 로 변경
- node, mysql 설치

<<<<<<< HEAD
## 💻사용 방법
1. DB_util.py에서 MYSQL의 id, pw 변경
2. PROXY_mitmproxy_script.py에서 탐색할 URL 화이트리스트에 입력
3. PROXY_mitmproxy.py 파일 실행
4. 이후 웹 브라우저를 돌아다니면 자동 탐지
=======
3. parameter 처리. 동일한 파라미터에 대한 여러 content_length 값을 row로 모아서 len_array에 전달. 파라미터가 다른 경우에는 이전 파라미터를 처리하고 새로운 파라미터 row를 시작함.

4. 최종적으로 하나의 url에 대한 파라미터값, content-Length로 구성된 이중리스트 형태의 len_array 생성
   ![image](https://github.com/Webf-killer/webfkiller/assets/80975083/6aadba02-0ee8-4a14-8e26-55c60d69918a)


#### check_len : 파싱된 데이터로부터 취약점을 판별하는 함수
1. url, len_array를 입력으로 받음

2. 배열의 각 요소(row)에 대해 첫번째 요소는 파라미터 이름, 나머지 요소는 값이 모두 같은지 확인

3. 값이 다른 요소가 하나만 있을 경우, 해당 row는 취약한 것으로 간주하고, DB_Control 모듈로 url, 파라미터 이름, True, 인덱스 번호 정보를 전송

## ⛳ 각 과정 별 input, output
#### 1. 패킷 생성하기
a. input : 프록시 url, 파라미터 이름, payloads_sqli.txt

b. output : 새로운 패킷

#### 2. 컴포저 불러오기
a. input : 새로운 패킷

b. output : 컴포저 응답의 url, 파라미터, 파라미터 갯수, 페이로드, Header의 Content-Lenght

#### 3. 취약점 탐지
a. input : 컴포저 응답의 url, 파라미터, 파라미터 갯수, 페이로드, Header의 Content-Length

b. output : 취약점 타입, url, 파라미터, 페이로드 => DB에 저장
>>>>>>> 0123cc6 (Update README.md)
