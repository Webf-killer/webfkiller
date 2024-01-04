# webfkiller
웹 페이지의 보안 취약점을 효과적으로 탐지하는 도구. 프록시 서버를 통해 데이터를 수집하고, 페이로드가 포함된 패킷을 보내서 취약점을 스캔하여 DB에 저장한다.

## 👯‍♀️ Member
- 김서율, 강경서, 구가경, 김수민, 김민지, 강혜인, 김우종

## 🎯 기능
1. **Crawler**:크롤링을 통해 url을 수집
2. **Proxy**: 프록시 서버를 통해 웹 페이지의 요청 및 응답 내용을 수집
3. **Scanner**: SQLi, Stored XSS, Reflected XSS, Dom-based XSS 취약점을 탐지
4. **Composer** : 페이로드를 이용한 패킷을 생성하고 요청 보냄
5. **DB** : 결과를 MySQL 데이터베이스에 저장
6. **Payload** : 취약점 탐지를 위한 다양한 페이로드들.

## ⭐설치 요구사항
- 필요한 파이썬 패키지 설치
  (requirements.txt파일에 필요한 패키지 이름 저장되어있음. 이 파일을 설치)
```python
pip install -r requirements.txt
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

#### node, mysql 설치


## 💻사용 방법
1. **USER_INPUT.py**에서 DB연결정보 입력하기(mysql_id,mysql_pw,mysql_host,mysql_port),
   탐지url(최상위 url)입력하기
2. **PROXY_mitmproxy.py** 파일 실행
3. 2번실행 후 열리는 셀레니움 창 돌아다니면서 자동 탐지<br/>
3.1. 셀레니움 창 자동 탐지하며 command창 확인
5. **Result폴더**의 **make_json.py**파일 실행
6. 4번 실행 후 **최상위url.json** 파일확인
=======




>>>>>>> 0123cc6 (Update README.md)
