#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <netinet/in.h> // for uint8_t
#include <string.h>
#include <map>
#include <tuple>
using namespace std;

#pragma pack(push,1)
struct radiotap_header  // 24byte
{
    uint8_t header_version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag[2];
    uint8_t flag;
    uint8_t data_rate;
    uint16_t channel_frequency;
    uint16_t channel_flag;
    uint16_t ssi_signal;    // 8byte + dummy?
    uint16_t rx_flag;
    uint8_t ssi_signal2;    // PWR
    uint8_t antenna;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_header    // 24byte
{
    uint16_t frame_control_field;
    uint16_t duration;
    uint8_t recv_dest_addr[6];  // receiver, destination address
    uint8_t trans_src_addr[6];  // transmitter, source address
    uint8_t bss_id[6];
    uint16_t frag_seq_num;  // fagment, sequence number
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wireless_header
{
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capabilities_info;
    uint8_t ssid_pra_set;
    uint8_t ssid_len;
};
#pragma pack(pop)

class PrintInfo
{
private:
    // BSSID, PWR, CH, ESSID
    uint8_t BSSID[6];
    uint8_t PWR;
    uint16_t CH;
    char MB[4];
    char ENC[4];
    uint8_t *ESSID;
    uint8_t beacon = 0;

public:
    PrintInfo(uint8_t *bssid, uint8_t pwr, uint16_t ch, uint8_t *essid, uint8_t essid_len, uint16_t enc, uint8_t mb);
    int getAbit(unsigned short x, int n)    // for ENC
    {
      return (x & (1 << n)) >> n;
    }
    void Show() const;
};


PrintInfo::PrintInfo(uint8_t *bssid, uint8_t pwr, uint16_t ch, uint8_t *essid, uint8_t essid_len, uint16_t enc, uint8_t mb)
{
    // BSSID Setting
    for(int i = 0; i < 6; i++)
    {
        BSSID[i] = *(bssid + i);
    }

    // PWR Setting
    PWR = ~pwr;
    PWR += 1;

    // Beacon Cout Setting
    beacon += 1;

    // CH Setting
    CH = ch % 2412 / 5 + 1;

    // MB Setting (Not parsing Qos, result -1, 802.11 etc...version)
    switch(mb)
    {
    case 0x02:
        strcpy(MB, "11");   // 802.11b
        break;

    case 0x0c:
        strcpy(MB, "54");   // 802.11g
        break;
    }

    // ENC Setting
    if(getAbit(enc, 4))
        strncpy(ENC, "CRT", 4);
    else
        strncpy(ENC, "OPN", 4);

    // ESSID Setting
    memcpy(&ESSID, &essid, essid_len);      //ha......I flew for 8 hours.
}

inline void PrintInfo::Show() const
{
    // Print BSSID
    printf(" ");
    for(int i = 0; i < 6; i++)
    {
        printf("%02X",BSSID[i]);
        if(i != 5)
            printf(":");
    }

    // Print PWR, CH, ESSID
    printf("  -%d                         %2d  %s   %s              %s\n", PWR, CH, MB, ENC, ESSID);
}

struct radiotap_header *radio;
struct beacon_header *beacon;
struct wireless_header *wireless;

void usage()
{
    printf("=========================== Usage ===========================\n");
    printf("root@ubuntu~$ ./airodump [interface]\n");
}

void print_menu(int check)
{
    if(check == 1)
    {
        printf(" CH  7 ][ Elapsed: 16 s ][ 2018-08-17 12:43\n\n");
        printf(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
    }

    if(check == 2)
    {
        printf(" BSSID              STATION            PWR   Rate    Lost    Frames  Probe\n\n");
    }
}

void printByHexData(u_int8_t *printArr, int length)
{
    for(int i=0;i<length;i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";
    }
    cout<<dec<<endl;
    //printLine();
}

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device : %s : %s\n", dev, errbuf);
        return -1;
    }

    system("clear");
    printf("Device : %s\n", dev);
    print_menu(1);

    map <uint64_t, uint16_t> key;
//    map <array<uint8_t, 6>, uint16_t> key;

    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        radio = (struct radiotap_header *)packet;
        packet += sizeof(struct radiotap_header);

        beacon = (struct beacon_header *)packet;
        packet += sizeof(struct beacon_header);

        wireless = (struct wireless_header *)packet;
        packet += sizeof(struct wireless_header);   // +14 byte for print ssid.

        uint8_t essid[wireless->ssid_len];
        memcpy(essid, packet, wireless->ssid_len);

        if(beacon->frame_control_field == 0x80)
        {
            uint64_t *b;
            uint16_t c = radio->channel_frequency;
            memcpy(&b, &beacon->bss_id, 6);

            pair<uint64_t*, uint16_t> key(b, c);
            PrintInfo x(beacon->bss_id, radio->ssi_signal2, radio->channel_frequency, essid, wireless->ssid_len, wireless->capabilities_info, radio->data_rate);
    //            PrintInfo *pCom;
    //            pCom = &x;
    //            pCom->Show();
            x.Show();
        }

        if(beacon->frame_control_field == 0x40)
        {
            print_menu(2);
            printf(" ");
            for(int i = 0; i < 6; i++)
            {
                printf("%02X",beacon->bss_id[i]);
                if(i != 5)
                    printf(":");
            }
            cout << endl << endl;
        }
    }
    pcap_close(handle);
    return 0;
}
