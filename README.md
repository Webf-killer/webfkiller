# webfkiller/attack/or.py & main.py
-김민지 담당
- url 에서 도메인 추출 (name)

(1) 웹드라이버 이용_클라이언트 측 라다이렉트 탐지 
웹페이지를 완전히 로드한 후의 상태(url)를 확인 \n
만약 리다이렉트 된 url (redirect url)이 '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우 (=다른 도메인으로 이동하는 경우) => 오픈 리다이렉트 탐지 

(2) location값 확인_ 서버 측에서 설정된 HTTP 리다이렉트를 감지 
 HTTP 상태 코드 300번대와 함께 'Location' 헤더를 포함하는지 확인
-> Location이  '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우 (=다른 도메인으로 이동하는 경우) => 오픈 리다이렉트 탐지 
