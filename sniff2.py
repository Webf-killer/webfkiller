# pip install scapy
# sniff 기능 사용위해서 npcap설치 필수
from scapy.all import *
from scapy.layers.inet import IP, TCP

requests = {}  # 요청 패킷 정보 저장 딕셔너리


# --------패킷 스니핑 구현-------
# 패킷 처리 함수
def process_packet(packet):
    # -----데이터 처리---------
    if IP in packet:  # 패킷에서 ip정보만 따옴
        ip_src = str(packet[IP].src)  # 출발지 주소
        ip_dst = str(packet[IP].dst)  # 목적주소
        ip_len = str(packet[IP].len)  # 바디크기

    if TCP in packet:  # 패킷에서 tcp정보만 따옴
        tcp_sprotocl = str(packet[TCP].sport)  # 프로토콜 종류
        if tcp_sprotocl == "80":
            tcp_sprotocl = "http"
        tcp_dprotocl = str(packet[TCP].dport)
        if tcp_dprotocl == "80":
            tcp_dprotocl = "http"

    if Raw in packet:
        Raw_load = str(packet[Raw].load)

    global requests

    # ------출력데이터 관리-----------
    if packet.haslayer(Raw):  # Raw 레이어 존재 확인
        # --------요청 패킷 잡기--------
        # Raw_load변수에 http 요청 메소드가 있을 경우만
        if any(
            method in Raw_load  # http 요청파트
            for method in [
                "POST",
                "GET",
                "PUT",
                "DELETE",
                "HEAD",
                "CONNECT",
                "OPTIONS",
                "TRACE",
                "PATCH",
            ]
        ):
            requests[(ip_src, tcp_sprotocl)] = (ip_dst, tcp_dprotocl)  # 요청 패킷 정보 저장
            print(
                "**요청**"
                + "\n"
                + "프로토콜 : "
                + tcp_sprotocl
                + ", "
                + tcp_dprotocl
                + "\n"
                + "출발주소 : "
                + ip_src
                + "\n"
                + "목적주소 : "
                + ip_dst
                + "\n"
                + "바디 : "
                + ip_len
                + "\n"
                + "RAW : "
                + Raw_load
            )
            print("--------------------------------")

        # 로우값만 앞에 데이터에 붙여서 출력
        # 앞부분 정보와 로우데이터 나눠서 변수 저장
        # 일괄 출력

        # -------응답 패킷 잡기------
        elif any(method in Raw_load for method in ["HTTP", "http"]):  # http 요청파트
            if (ip_dst, tcp_dprotocl) in requests and requests[
                (ip_dst, tcp_dprotocl)
            ] == (
                ip_src,
                tcp_sprotocl,
            ):  # 요청-응답 패킷 매칭 확인
                print(
                    "**응답**"
                    + "\n"
                    + "프로토콜 : "
                    + tcp_sprotocl
                    + ", "
                    + tcp_dprotocl
                    + "\n"
                    + "출발주소 : "
                    + ip_src
                    + "\n"
                    + "목적주소 : "
                    + ip_dst
                    + "\n"
                    + "바디 : "
                    + ip_len
                    + "\n"
                    + "RAW : "
                    + Raw_load
                )
                save_dst = {}
            print("--------------------------------")


# 패킷 캡처 시작
# prn=함수에 인자로 데이터 넘김
# store=저장1 모니터링0
sniff(prn=process_packet, store=False)


# http://www.kenca.or.kr/main/index.jsp 테스트 사이트
