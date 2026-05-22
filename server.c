/*
 * Collaborative Text Editor - Serwer TCP z WebSocket
 * Przetwarzanie Rozproszone - Etap II
 *
 * Przeciwdziała zagrożeniom:
 *   A) Race condition → mutex doc_mutex chroni bufor dokumentu
 *   B) Rozspójność listy klientów → mutex clients_mutex + obsługa SIGPIPE
 *   C) Partial reads / fragmentacja TCP → message framing ze znakiem '\n'
 *   D) Konflikty edycji → serwer jako Single Source of Truth + sequence ID
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
/* ── Wbudowana implementacja SHA-1 (RFC 3174) ── */
typedef struct { uint32_t s[5]; uint64_t count; uint8_t buf[64]; } SHA1_CTX;
#define ROL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
static void sha1_compress(SHA1_CTX *c){
    uint32_t w[80],a,b,d,e,f,k,t; int i;
    for(i=0;i<16;i++) w[i]=((uint32_t)c->buf[i*4]<<24)|((uint32_t)c->buf[i*4+1]<<16)|((uint32_t)c->buf[i*4+2]<<8)|c->buf[i*4+3];
    for(i=16;i<80;i++) w[i]=ROL32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    a=c->s[0];b=c->s[1];uint32_t cc=c->s[2];d=c->s[3];e=c->s[4];
    for(i=0;i<80;i++){
        if(i<20){f=(b&cc)|(~b&d);k=0x5A827999;}
        else if(i<40){f=b^cc^d;k=0x6ED9EBA1;}
        else if(i<60){f=(b&cc)|(b&d)|(cc&d);k=0x8F1BBCDC;}
        else{f=b^cc^d;k=0xCA62C1D6;}
        t=ROL32(a,5)+f+e+k+w[i]; e=d;d=cc;cc=ROL32(b,30);b=a;a=t;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;
}
static void sha1_init(SHA1_CTX *c){
    c->s[0]=0x67452301;c->s[1]=0xEFCDAB89;c->s[2]=0x98BADCFE;c->s[3]=0x10325476;c->s[4]=0xC3D2E1F0;c->count=0;
}
static void sha1_update(SHA1_CTX *c,const uint8_t *d,size_t n){
    size_t r=c->count%64; c->count+=n;
    if(r){size_t l=64-r; if(n<l){memcpy(c->buf+r,d,n);return;} memcpy(c->buf+r,d,l);sha1_compress(c);d+=l;n-=l;}
    for(;n>=64;d+=64,n-=64){memcpy(c->buf,d,64);sha1_compress(c);}
    if(n) memcpy(c->buf,d,n);
}
static void sha1_final(SHA1_CTX *c,uint8_t *out){
    uint8_t p[64]={0}; size_t r=c->count%64; p[0]=0x80;
    if(r<56){sha1_update(c,p,56-r);}else{sha1_update(c,p,64-r+56);}
    uint64_t bits=c->count*8;
    uint8_t l[8]; for(int i=7;i>=0;i--){l[i]=bits&0xFF;bits>>=8;}
    sha1_update(c,l,8);
    for(int i=0;i<5;i++){out[i*4]=(c->s[i]>>24)&0xFF;out[i*4+1]=(c->s[i]>>16)&0xFF;out[i*4+2]=(c->s[i]>>8)&0xFF;out[i*4+3]=c->s[i]&0xFF;}
}
static void SHA1(const uint8_t *d,size_t n,uint8_t *out){SHA1_CTX c;sha1_init(&c);sha1_update(&c,d,n);sha1_final(&c,out);}

/* ── Wbudowana implementacja Base64 (RFC 4648) ── */
static const char b64t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char *base64_encode_impl(const unsigned char *data,size_t len){
    size_t out_len=4*((len+2)/3); char *out=malloc(out_len+1);
    size_t i,j; for(i=0,j=0;i<len;){
        uint32_t v=0; int pad=0;
        v=(uint32_t)data[i++]<<16;
        if(i<len)v|=(uint32_t)data[i++]<<8; else pad++;
        if(i<len)v|=data[i++]; else pad++;
        out[j++]=b64t[(v>>18)&63]; out[j++]=b64t[(v>>12)&63];
        out[j++]=(pad>=2)?'=':b64t[(v>>6)&63];
        out[j++]=(pad>=1)?'=':b64t[v&63];
    } out[j]='\0'; return out;
}

/* ─── Stałe ─────────────────────────────────────────────────────────────── */
#define PORT          5000
#define MAX_CLIENTS   64
#define MAX_DOC_SIZE  65536
#define RECV_BUF_SIZE 4096
#define FRAME_BUF_SIZE 8192

/* ─── Stan globalny ──────────────────────────────────────────────────────── */

/* Zagrożenie A: doc_mutex chroni dokument i sequence_id */
static char             document[MAX_DOC_SIZE] = "";
static int              doc_len                = 0;
static unsigned long    sequence_id            = 0;
static pthread_mutex_t  doc_mutex              = PTHREAD_MUTEX_INITIALIZER;

/* Zagrożenie B: clients_mutex chroni tablicę deskryptorów */
static int              clients[MAX_CLIENTS];
static int              client_count           = 0;
static pthread_mutex_t  clients_mutex          = PTHREAD_MUTEX_INITIALIZER;

/* ─── Alias ──────────────────────────────────────────────────────────────── */
#define base64_encode base64_encode_impl

/* ─── WebSocket handshake ────────────────────────────────────────────────── */
static int ws_handshake(int sock) {
    char buf[2048] = {0};
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;

    /* Wyłów Sec-WebSocket-Key */
    char *key_start = strstr(buf, "Sec-WebSocket-Key:");
    if (!key_start) return -1;
    key_start += 18;
    while (*key_start == ' ') key_start++;
    char client_key[128] = {0};
    int i = 0;
    while (key_start[i] != '\r' && key_start[i] != '\n' && i < 127) {
        client_key[i] = key_start[i];
        i++;
    }
    client_key[i] = '\0';

    /* SHA1(key + magic) → Base64 */
    char combined[256];
    snprintf(combined, sizeof(combined),
             "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    uint8_t sha1[20];
    SHA1((const uint8_t *)combined, strlen(combined), sha1);
    char *accept = base64_encode(sha1, 20);

    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    free(accept);

    int sent = write(sock, response, strlen(response));
    return (sent > 0) ? 0 : -1;
}

/* ─── WebSocket ramki ────────────────────────────────────────────────────── */

/*
 * Wyślij tekst jako ramkę WebSocket (text frame, FIN=1, bez maskowania).
 * Zagrożenie B: używamy osobno clients_mutex przed wywołaniem,
 * więc tutaj nie blokujemy — send() samo w sobie jest bezpieczne na gnieździe.
 */
static int ws_send(int sock, const char *msg, size_t len) {
    unsigned char frame[FRAME_BUF_SIZE + 10];
    int header_len;

    frame[0] = 0x81; /* FIN + opcode text */
    if (len <= 125) {
        frame[1] = (unsigned char)len;
        header_len = 2;
    } else if (len <= 65535) {
        frame[1] = 126;
        frame[2] = (len >> 8) & 0xFF;
        frame[3] = len & 0xFF;
        header_len = 4;
    } else {
        return -1; /* za duże */
    }
    memcpy(frame + header_len, msg, len);
    return write(sock, frame, header_len + len);
}

/*
 * Odczytaj jedną ramkę WebSocket z gniazda.
 * Zagrożenie C: nie używamy surowego recv() na danych aplikacji —
 * odczytujemy nagłówek ramki WS (który sam zawiera długość) i dopiero
 * potem dokładnie tyle bajtów payload. To osobny poziom framingu od TCP.
 * Zwraca długość payloadu lub <=0 przy błędzie/rozłączeniu.
 */
static int ws_recv(int sock, char *out, size_t out_size) {
    unsigned char header[2];
    if (recv(sock, header, 2, MSG_WAITALL) != 2) return -1;

    /* int fin  = (header[0] >> 7) & 1; */
    int opcode = header[0] & 0x0F;
    if (opcode == 0x8) return 0;  /* close frame */

    int masked     = (header[1] >> 7) & 1;
    size_t payload = header[1] & 0x7F;

    if (payload == 126) {
        unsigned char ext[2];
        if (recv(sock, ext, 2, MSG_WAITALL) != 2) return -1;
        payload = (ext[0] << 8) | ext[1];
    } else if (payload == 127) {
        return -1; /* nie obsługujemy >65535 */
    }

    unsigned char mask[4] = {0};
    if (masked) {
        if (recv(sock, mask, 4, MSG_WAITALL) != 4) return -1;
    }

    if (payload >= out_size) return -1;

    /* Zagrożenie C: MSG_WAITALL gwarantuje odczyt dokładnie payload bajtów */
    if (recv(sock, out, payload, MSG_WAITALL) != (ssize_t)payload) return -1;

    if (masked) {
        for (size_t i = 0; i < payload; i++)
            out[i] ^= mask[i % 4];
    }
    out[payload] = '\0';
    return (int)payload;
}

/* ─── Broadcast ──────────────────────────────────────────────────────────── */

/*
 * Rozsyła wiadomość do wszystkich klientów oprócz nadawcy.
 * Zagrożenie B: blokujemy clients_mutex na czas iteracji.
 * Sygnał SIGPIPE jest ignorowany globalnie — write() do rozłączonego
 * gniazda zwróci -1/EPIPE zamiast ubijać proces.
 */
static void broadcast(int sender_sock, const char *msg, size_t len) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i] != sender_sock) {
            ws_send(clients[i], msg, len);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/* Wyślij do WSZYSTKICH (łącznie z nadawcą) — do init state */
static void send_to_one(int sock, const char *msg, size_t len) {
    ws_send(sock, msg, len);
}

/* ─── Zarządzanie listą klientów ─────────────────────────────────────────── */
static void client_add(int sock) {
    pthread_mutex_lock(&clients_mutex);
    if (client_count < MAX_CLIENTS)
        clients[client_count++] = sock;
    pthread_mutex_unlock(&clients_mutex);
}

static void client_remove(int sock) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i] == sock) {
            clients[i] = clients[--client_count];
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/* ─── Aplikowanie operacji na dokumencie ─────────────────────────────────── */

/*
 * Format wiadomości (JSON uproszczony, rozdzielony '\n' — framing):
 *   {"type":"edit","pos":5,"del":2,"ins":"abc"}
 *
 * Zagrożenie A: całość pod doc_mutex — sekwencyjny dostęp.
 * Zagrożenie D: serwer jest Single Source of Truth; inkrementuje seq_id
 *               i odsyła autorytatywny stan.
 *
 * Zwraca 0 gdy ok, -1 gdy błędna operacja.
 */
static int apply_edit(int pos, int del, const char *ins, int ins_len) {
    /* walidacja zakresu */
    if (pos < 0 || pos > doc_len) return -1;
    if (pos + del > doc_len) del = doc_len - pos;

    int new_len = doc_len - del + ins_len;
    if (new_len >= MAX_DOC_SIZE) return -1;

    /* przesuń ogon dokumentu */
    memmove(document + pos + ins_len,
            document + pos + del,
            doc_len - pos - del);

    /* wstaw nowy tekst */
    memcpy(document + pos, ins, ins_len);
    doc_len = new_len;
    document[doc_len] = '\0';
    sequence_id++;
    return 0;
}

/* ─── Pomocnik: prosta ekstrakcja pola JSON (bez pełnego parsera) ─────────── */
static int json_int(const char *json, const char *key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    while (*p == ' ') p++;
    return atoi(p);
}

/* Wyłów wartość stringa z JSON: "key":"value" → value (do buf, max maxlen) */
static int json_str(const char *json, const char *key, char *buf, int maxlen) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(json, search);
    if (!p) { buf[0] = '\0'; return 0; }
    p += strlen(search);
    int i = 0;
    while (*p && *p != '"' && i < maxlen - 1) {
        /* obsługa \n, \t itp. */
        if (*p == '\\' && *(p+1)) {
            p++;
            switch(*p) {
                case 'n':  buf[i++] = '\n'; break;
                case 't':  buf[i++] = '\t'; break;
                case '"':  buf[i++] = '"';  break;
                case '\\': buf[i++] = '\\'; break;
                default:   buf[i++] = *p;   break;
            }
        } else {
            buf[i++] = *p;
        }
        p++;
    }
    buf[i] = '\0';
    return i;
}

/* Prosta ucieczka znaków specjalnych JSON w tekście */
static int json_escape(const char *src, char *dst, int maxlen) {
    int j = 0;
    for (int i = 0; src[i] && j < maxlen - 2; i++) {
        switch(src[i]) {
            case '"':  dst[j++]='\\'  ; dst[j++]='"';  break;
            case '\\': dst[j++]='\\' ; dst[j++]='\\'; break;
            case '\n': dst[j++]='\\' ; dst[j++]='n';  break;
            case '\r': dst[j++]='\\' ; dst[j++]='r';  break;
            case '\t': dst[j++]='\\' ; dst[j++]='t';  break;
            default:   dst[j++]=src[i];                break;
        }
    }
    dst[j] = '\0';
    return j;
}

/* ─── Wątek obsługi klienta ──────────────────────────────────────────────── */
static void *connection_handler(void *arg) {
    int sock = *(int *)arg;
    free(arg);

    /* WebSocket handshake */
    if (ws_handshake(sock) != 0) {
        close(sock);
        pthread_exit(NULL);
    }

    /* Rejestracja klienta (Zagrożenie B) */
    client_add(sock);
    fprintf(stderr, "[+] Klient fd=%d połączony. Aktywni: %d\n", sock, client_count);

    /* Wyślij aktualny stan dokumentu (Zagrożenie D: Single Source of Truth) */
    {
        char esc[MAX_DOC_SIZE * 2];
        char msg[MAX_DOC_SIZE * 2 + 128];
        pthread_mutex_lock(&doc_mutex);
        json_escape(document, esc, sizeof(esc));
        int mlen = snprintf(msg, sizeof(msg),
            "{\"type\":\"init\",\"seq\":%lu,\"content\":\"%s\"}",
            sequence_id, esc);
        pthread_mutex_unlock(&doc_mutex);
        send_to_one(sock, msg, mlen);
    }

    /* Pętla odbioru — Zagrożenie C: ws_recv obsługuje framing */
    char frame[FRAME_BUF_SIZE];
    int n;
    while ((n = ws_recv(sock, frame, sizeof(frame))) > 0) {
        /* Oczekujemy: {"type":"edit","pos":N,"del":N,"ins":"..."} */
        char type[32];
        json_str(frame, "type", type, sizeof(type));
        if (strcmp(type, "edit") != 0) continue;

        int pos = json_int(frame, "pos");
        int del = json_int(frame, "del");
        char ins[FRAME_BUF_SIZE];
        int ins_len = json_str(frame, "ins", ins, sizeof(ins));

        if (pos < 0) pos = 0;
        if (del < 0) del = 0;

        /* Zagrożenie A: mutex przed modyfikacją dokumentu */
        pthread_mutex_lock(&doc_mutex);
        int ok = apply_edit(pos, del, ins, ins_len);
        unsigned long seq = sequence_id;
        char esc[MAX_DOC_SIZE * 2];
        json_escape(document, esc, sizeof(esc));
        pthread_mutex_unlock(&doc_mutex);

        if (ok != 0) continue;

        /* Zagrożenie D: rozsyłamy autorytatywny stan z numerem sekwencji */
        char msg[MAX_DOC_SIZE * 2 + 256];
        int mlen = snprintf(msg, sizeof(msg),
            "{\"type\":\"update\",\"seq\":%lu,\"pos\":%d,\"del\":%d,"
            "\"ins\":\"%s\",\"content\":\"%s\"}",
            seq, pos, del, ins, esc);

        /* Odesłaj potwierdzenie nadawcy + broadcast do pozostałych */
        send_to_one(sock, msg, mlen);
        broadcast(sock, msg, mlen);
    }

    /* Rozłączenie — Zagrożenie B: usuń z listy pod muteksem */
    client_remove(sock);
    close(sock);
    fprintf(stderr, "[-] Klient fd=%d rozłączony. Aktywni: %d\n", sock, client_count);
    pthread_exit(NULL);
}

/* ─── main ───────────────────────────────────────────────────────────────── */
int main(void) {
    /* Zagrożenie B: ignorujemy SIGPIPE — zapis do zamkniętego gniazda
     * zwróci EPIPE zamiast ubijać proces */
    signal(SIGPIPE, SIG_IGN);

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(PORT);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(listenfd, 10);
    fprintf(stderr, "Serwer nasłuchuje na porcie %d...\n", PORT);

    for (;;) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) { perror("accept"); continue; }

        int *arg = malloc(sizeof(int));
        *arg = connfd;

        pthread_t tid;
        if (pthread_create(&tid, NULL, connection_handler, arg) != 0) {
            perror("pthread_create");
            free(arg);
            close(connfd);
        } else {
            pthread_detach(tid);
        }
    }
}
