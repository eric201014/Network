#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>

struct data {
    int num;
    char ip[200];
};

struct data total[1000];
int t = 0;

void getP (u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int *id = (int *) arg, i;
    char tmp[200];
    printf ("id: %d\n", ++ (*id));
    printf ("Recieved time: %s", ctime ( (const time_t *) &pkthdr->ts.tv_sec));
    printf ("\nMAC Address From: ");
    for (i = 0; i < 6; i++)
        printf ("%02x ", packet[i]);
    printf ("\nMAC Adress To: ");
    for (i = 6; i < 12; i++)
        printf ("%02x ", packet[i]);
    printf ("\n");
    int type1 = packet[12], type2 = packet[13];
    if (type1 == 8 && type2 == 0) { //IP
        printf ("Type: IP\n");
        printf ("Src IP Address: ");
        for (i = 26; i < 29; i++)
            printf ("%d.", packet[i]);
        printf ("%d", packet[29]);
        printf ("\nDst IP Address: ");
        for (i = 30; i < 33; i++)
            printf ("%d.", packet[i]);
        printf ("%d", packet[33]);
        printf ("\nProtocol: ");
        if (packet[23] == 6)
            printf ("TCP");
        else if (packet[23] == 17)
            printf ("UDP");
        else
            printf ("Else");
        printf("\n");
        if (packet[23] == 6 || packet[23] == 17) {
            printf ("Src port: %d\n", packet[34] * 256 + packet[35]);
            printf ("Dst port: %d\n", packet[36] * 256 + packet[37]);
            sprintf (tmp, "[%d.%d.%d.%d] to [%d.%d.%d.%d]", packet[26], packet[27], packet[28], packet[29], packet[30], packet[31], packet[32], packet[33]);
        }

        int check = 0;
        for (i = 0; i < t; i++)
            if (!strcmp (total[i].ip, tmp)) {
                check = 1;
                total[i].num++;
                break;
            }
        if (check == 0) {
            total[t].num = 1;
            strcpy (total[t].ip, tmp);
            t++;
        }
    }

    

    printf ("\n\n");
}

int main (int argc, char **argv) {
    char errBuf[PCAP_ERRBUF_SIZE], *name, filename[100] = "";
    for (int t = 0; t < 1000; t++ ) total->num = 0;
    name = pcap_lookupdev (errBuf);
    if (name) 
        printf ("success! device: %s\n", name);
    else {
        printf ("fail! %s\n", errBuf);
        exit (1);
    }

    int n = -1, id = 0, i;
    pcap_t *device = pcap_open_live (name, 65535, 1, 0, errBuf);
    if (argc == 3) {
        if (!strcmp (argv[1], "-r")) {
            strcpy (filename, argv[2]);
            device = pcap_open_offline (filename, errBuf);
            if (!device) {
                fprintf (stderr, "pcap_open_offline(): %s\n", errBuf);
                exit (1);
            }
            printf ("Open: %s\n", filename);
        } 
        else 
            return 0;
    }

    pcap_loop (device, n, getP, (u_char *) &id);
    printf ("\n----------------\n");
    for (i = 0; i < t; i++)
        printf ("%s  %d\n", total[i].ip, total[i].num);
    pcap_close (device);

    return 0;
}
