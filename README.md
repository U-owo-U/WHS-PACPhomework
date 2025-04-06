# WHS-PACPhomework
설명란 - 깃허브 처음 써봐요


#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>

#define SNAP_LEN 1518  // 캡처할 최대 바이트 수

/* 패킷 처리 콜백 함수 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const int ethernet_header_length = 14;  // Ethernet 헤더 길이

    if (header->len < ethernet_header_length) {
        printf("패킷 길이가 너무 짧습니다.\n");
        return;
    }

    /* IP 헤더 포인터 설정 (Ethernet 헤더 이후) */
    const struct ip *ip_hdr = (struct ip*)(packet + ethernet_header_length);
    int ip_header_length = ip_hdr->ip_hl * 4;
    if (ip_header_length < 20) {
        printf("잘못된 IP 헤더 길이: %d 바이트\n", ip_header_length);
        return;
    }

    /* TCP 프로토콜이 아닌 경우 리턴 */
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;
    }

    /* TCP 헤더 포인터 설정 */
    const struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + ethernet_header_length + ip_header_length);

    /* 패킷 정보 출력 */
    printf("패킷 캡처됨:\n");
    printf("    출발지 IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("    목적지 IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
    printf("    출발지 포트: %d\n", ntohs(tcp_hdr->source));
    printf("    목적지 포트: %d\n", ntohs(tcp_hdr->dest));
    printf("    시퀀스 번호: %u\n", ntohl(tcp_hdr->seq));
    printf("    ACK 번호: %u\n", ntohl(tcp_hdr->ack_seq));
    printf("--------------------------------------\n");
}

int main(int argc, char **argv) {
    char *dev = NULL;                  // 캡처 장치 이름
    char errbuf[PCAP_ERRBUF_SIZE];       // 에러 버퍼
    pcap_t *handle;                    // 패킷 캡처 핸들
    struct bpf_program fp;             // 컴파일된 필터 프로그램
    char filter_exp[] = "tcp";         // 필터 표현식 (TCP 패킷만 캡처)
    bpf_u_int32 net;                   // 네트워크 주소
    bpf_u_int32 mask;                  // 서브넷 마스크

    /* 명령행 인자로 캡처 장치가 주어지지 않은 경우 기본 장치 검색 */
    if (argc == 2) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "장치 검색 오류: %s\n", errbuf);
            return 2;
        }
    }

    /* 캡처 장치의 네트워크 주소와 서브넷 마스크 얻기 */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "네트워크 정보 검색 오류: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    /* 캡처 장치 열기 */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 열기 실패: %s\n", errbuf);
        return 2;
    }

    /* 필터 컴파일 */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile() 실패: %s\n", pcap_geterr(handle));
        return 2;
    }

    /* 필터 적용 */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter() 실패: %s\n", pcap_geterr(handle));
        return 2;
    }

    printf("패킷 캡처 시작 (장치: %s)\n", dev);
    /* 패킷 캡처 시작 */
    pcap_loop(handle, 0, packet_handler, NULL);

    /* 자원 해제 */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
