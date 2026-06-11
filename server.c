#include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <string.h>
 #include <pthread.h>
 #include <signal.h>
 #include <stdint.h>
 
 /* SHA1 */
 static void sha1(const uint8_t *msg, size_t len, uint8_t *out) {
     uint32_t h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
     size_t plen = len + 1;
     while(plen % 64 != 56) plen++;
     plen += 8;
     uint8_t *p = calloc(plen, 1);
     memcpy(p, msg, len);
     p[len] = 0x80;
     uint64_t bits = (uint64_t)len * 8;
     for(int i=0;i<8;i++) p[plen-8+i]=(bits>>(56-8*i))&0xFF;
     for(size_t off=0;off<plen;off+=64){
         uint32_t w[80];
         for(int i=0;i<16;i++)
             w[i]=((uint32_t)p[off+i*4]<<24)|((uint32_t)p[off+i*4+1]<<16)|
                  ((uint32_t)p[off+i*4+2]<<8)|p[off+i*4+3];
         for(int i=16;i<80;i++){uint32_t t=w[i-3]^w[i-8]^w[i-14]^w[i-16];w[i]=(t<<1)|(t>>31);}
         uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
         for(int i=0;i<80;i++){
             uint32_t f,k;
             if(i<20){f=(b&c)|(~b&d);k=0x5A827999;}
             else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
             else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
             else{f=b^c^d;k=0xCA62C1D6;}
             uint32_t t=((a<<5)|(a>>27))+f+e+k+w[i];
             e=d;d=c;c=(b<<30)|(b>>2);b=a;a=t;
         }
         h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;
     }
     free(p);
     uint32_t hh[5]={h0,h1,h2,h3,h4};
     for(int i=0;i<5;i++){
         out[i*4]=(hh[i]>>24)&0xFF;out[i*4+1]=(hh[i]>>16)&0xFF;
         out[i*4+2]=(hh[i]>>8)&0xFF;out[i*4+3]=hh[i]&0xFF;
     }
 }
 
 /* Base64 */
 static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 static char *b64enc(const uint8_t *d, size_t len){
     size_t ol=4*((len+2)/3); char *o=malloc(ol+1);
     size_t i,j;
     for(i=0,j=0;i<len;){
         uint32_t v=0; int pad=0;
         v=(uint32_t)d[i++]<<16;
         if(i<len)v|=(uint32_t)d[i++]<<8; else pad++;
         if(i<len)v|=d[i++]; else pad++;
         o[j++]=B64[(v>>18)&63];o[j++]=B64[(v>>12)&63];
         o[j++]=(pad>=2)?'=':B64[(v>>6)&63];
         o[j++]=(pad>=1)?'=':B64[v&63];
     }
     o[j]='\0';return o;
 }
 
 /* Stałe */
 #define PORT           8080
 #define MAX_CLIENTS    64
 #define MAX_DOC_SIZE   65536
 #define FRAME_BUF_SIZE 8192
 
 /* HTML */
 /* WebSocket */
 static const char HTML[] =
 "<!DOCTYPE html>\n"
 "<html lang='pl'>\n"
 "<head>\n"
 "<meta charset='UTF-8'>\n"
 "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
 "<title>Collaborative Text Editor</title>\n"
 "<style>\n"
 "* { box-sizing: border-box; margin: 0; padding: 0; }\n"
 "body { font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e2e; color: #cdd6f4; height: 100vh; display: flex; flex-direction: column; }\n"
 "header { background: #181825; border-bottom: 1px solid #313244; padding: 10px 20px; display: flex; align-items: center; gap: 16px; }\n"
 "header h1 { font-size: 16px; font-weight: 600; color: #cba6f7; }\n"
 "#status { font-size: 12px; padding: 3px 10px; border-radius: 20px; font-weight: 500; }\n"
 "#status.connecting { background: #f38ba822; color: #f38ba8; }\n"
 "#status.connected  { background: #a6e3a122; color: #a6e3a1; }\n"
 "#status.disconnected { background: #45475a; color: #6c7086; }\n"
 "#seq-display { margin-left: auto; font-size: 11px; color: #6c7086; font-family: monospace; }\n"
 "#users-display { font-size: 11px; color: #89b4fa; }\n"
 "main { flex: 1; display: flex; overflow: hidden; }\n"
 "#editor-wrap { flex: 1; display: flex; flex-direction: column; padding: 16px; gap: 8px; }\n"
 "#editor { flex: 1; background: #11111b; color: #cdd6f4; border: 1px solid #313244; border-radius: 8px; padding: 16px; font-family: 'Cascadia Code','Fira Code','Consolas',monospace; font-size: 14px; line-height: 1.6; resize: none; outline: none; transition: border-color 0.2s; }\n"
 "#editor:focus { border-color: #cba6f7; }\n"
 "#editor:disabled { opacity: 0.4; cursor: not-allowed; }\n"
 "#log-panel { width: 260px; background: #181825; border-left: 1px solid #313244; display: flex; flex-direction: column; overflow: hidden; }\n"
 "#log-header { padding: 10px 14px; font-size: 11px; font-weight: 600; color: #89b4fa; border-bottom: 1px solid #313244; text-transform: uppercase; letter-spacing: 0.5px; }\n"
 "#log { flex: 1; overflow-y: auto; padding: 8px; font-family: monospace; font-size: 11px; display: flex; flex-direction: column; gap: 2px; }\n"
 ".log-entry { padding: 3px 6px; border-radius: 4px; line-height: 1.4; word-break: break-all; }\n"
 ".log-entry.sent { color: #89dceb; background: #89dceb11; }\n"
 ".log-entry.recv { color: #a6e3a1; background: #a6e3a111; }\n"
 ".log-entry.sys  { color: #f9e2af; background: #f9e2af11; }\n"
 ".log-entry.error{ color: #f38ba8; background: #f38ba811; }\n"
 "</style>\n"
 "</head>\n"
 "<body>\n"
 "<header>\n"
 "  <h1>&#128221; Collaborative Text Editor</h1>\n"
 "  <span id='status' class='connecting'>&#9679; łączenie&hellip;</span>\n"
 "  <span id='users-display'>&ndash;</span>\n"
 "  <span id='seq-display'>seq: &ndash;</span>\n"
 "</header>\n"
 "<main>\n"
 "  <div id='editor-wrap'>\n"
 "    <textarea id='editor' placeholder='Połącz z serwerem&hellip;' disabled></textarea>\n"
 "  </div>\n"
 "  <div id='log-panel'>\n"
 "    <div id='log-header'>&#128225; Log komunikacji</div>\n"
 "    <div id='log'></div>\n"
 "  </div>\n"
 "</main>\n"
 "<script>\n"
 "/* WebSocket */\n"
 "const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';\n"
 "const WS_URL = proto + '//' + location.host;\n"
 "let ws = null, localSeq = 0, ignoreInput = false, lastContent = '';\n"
 "const editor = document.getElementById('editor');\n"
 "const statusEl = document.getElementById('status');\n"
 "const seqEl = document.getElementById('seq-display');\n"
 "const usersEl = document.getElementById('users-display');\n"
 "const logEl = document.getElementById('log');\n"
 "function addLog(cls, text) {\n"
 "  const el = document.createElement('div');\n"
 "  el.className = 'log-entry ' + cls;\n"
 "  el.textContent = text;\n"
 "  logEl.appendChild(el);\n"
 "  logEl.scrollTop = logEl.scrollHeight;\n"
 "  while (logEl.children.length > 200) logEl.removeChild(logEl.firstChild);\n"
 "}\n"
 "function setStatus(state, text) {\n"
 "  statusEl.className = 'status ' + state;\n"
 "  statusEl.textContent = '\\u25cf ' + text;\n"
 "}\n"
 "function connect() {\n"
 "  setStatus('connecting', 'łączenie\\u2026');\n"
 "  addLog('sys', '\\u2192 Łączę z ' + WS_URL);\n"
 "  ws = new WebSocket(WS_URL);\n"
 "  ws.onopen = () => { setStatus('connected', 'połączono'); editor.disabled = false; addLog('sys', '\\u2713 Połączono z serwerem'); };\n"
 "  ws.onclose = () => { setStatus('disconnected', 'rozłączono'); editor.disabled = true; addLog('sys', '\\u2717 Rozłączono \\u2014 ponawiam za 3s\\u2026'); setTimeout(connect, 3000); };\n"
 "  ws.onerror = () => { addLog('error', '\\u2717 Błąd WebSocket'); };\n"
 "  ws.onmessage = (event) => {\n"
 "    let msg; try { msg = JSON.parse(event.data); } catch { return; }\n"
 "    addLog('recv', '\\u2190 ' + msg.type + ' seq=' + msg.seq);\n"
 "    seqEl.textContent = 'seq: ' + msg.seq;\n"
 "    localSeq = msg.seq;\n"
 "    if (msg.type === 'init' || msg.type === 'update') {\n"
 "      ignoreInput = true;\n"
 "      const selStart = editor.selectionStart, selEnd = editor.selectionEnd;\n"
 "      const prevLen = editor.value.length;\n"
 "      editor.value = msg.content;\n"
 "      lastContent = msg.content;\n"
 "      if (msg.type === 'update') {\n"
 "        const delta = msg.content.length - prevLen;\n"
 "        editor.selectionStart = Math.max(0, selStart + (selStart >= msg.pos ? delta : 0));\n"
 "        editor.selectionEnd   = Math.max(0, selEnd   + (selEnd   >= msg.pos ? delta : 0));\n"
 "      }\n"
 "      ignoreInput = false;\n"
 "    }\n"
 "  };\n"
 "}\n"
 "editor.addEventListener('input', () => {\n"
 "  if (ignoreInput || !ws || ws.readyState !== WebSocket.OPEN) return;\n"
 "  const newVal = editor.value, oldVal = lastContent;\n"
 "  let start = 0;\n"
 "  while (start < oldVal.length && start < newVal.length && oldVal[start] === newVal[start]) start++;\n"
 "  let oldEnd = oldVal.length, newEnd = newVal.length;\n"
 "  while (oldEnd > start && newEnd > start && oldVal[oldEnd-1] === newVal[newEnd-1]) { oldEnd--; newEnd--; }\n"
 "  const deleted = oldEnd - start;\n"
 "  const inserted = newVal.slice(start, newEnd);\n"
 "  lastContent = newVal;\n"
 "  const op = { type: 'edit', pos: start, del: deleted, ins: inserted };\n"
 "  addLog('sent', '\\u2192 edit pos=' + start + ' del=' + deleted + ' ins=\"' + inserted.slice(0,20) + '\"');\n"
 "  ws.send(JSON.stringify(op));\n"
 "});\n"
 "connect();\n"
 "</script>\n"
 "</body>\n"
 "</html>\n";
 
 /* Globalne */
 static char            document[MAX_DOC_SIZE] = "";
 static int             doc_len                = 0;
 static unsigned long   sequence_id            = 0;
 static pthread_mutex_t doc_mutex              = PTHREAD_MUTEX_INITIALIZER;
 
 static int             clients[MAX_CLIENTS];
 static int             client_count           = 0;
 static pthread_mutex_t clients_mutex          = PTHREAD_MUTEX_INITIALIZER;
 
 static char g_esc[MAX_DOC_SIZE * 2];
 static char g_msg[MAX_DOC_SIZE * 2 + 256];
 
 /* JSON */
 static int json_escape(const char *src, char *dst, int maxlen){
     int j=0;
     for(int i=0;src[i]&&j<maxlen-2;i++){
         switch(src[i]){
             case '"': dst[j++]='\\';dst[j++]='"';break;
             case '\\':dst[j++]='\\';dst[j++]='\\';break;
             case '\n':dst[j++]='\\';dst[j++]='n';break;
             case '\r':dst[j++]='\\';dst[j++]='r';break;
             case '\t':dst[j++]='\\';dst[j++]='t';break;
             default:  dst[j++]=src[i];
         }
     }
     dst[j]='\0';return j;
 }
 static int json_int(const char *json, const char *key){
     char s[64]; snprintf(s,sizeof(s),"\"%s\":",key);
     const char *p=strstr(json,s); if(!p) return -1;
     p+=strlen(s); while(*p==' ')p++; return atoi(p);
 }
 static int json_str(const char *json, const char *key, char *buf, int maxlen){
     char s[64]; snprintf(s,sizeof(s),"\"%s\":\"",key);
     const char *p=strstr(json,s); if(!p){buf[0]='\0';return 0;}
     p+=strlen(s); int i=0;
     while(*p&&*p!='"'&&i<maxlen-1){
         if(*p=='\\'&&*(p+1)){
             p++;
             switch(*p){
                 case 'n': buf[i++]='\n';break;
                 case 't': buf[i++]='\t';break;
                 case '"': buf[i++]='"';break;
                 case '\\':buf[i++]='\\';break;
                 default:  buf[i++]=*p;
             }
         } else { buf[i++]=*p; }
         p++;
     }
     buf[i]='\0';return i;
 }
 
 /* HTML */
 static void serve_html(int sock) {
     size_t hlen = strlen(HTML);
     char header[256];
     int hdrlen = snprintf(header, sizeof(header),
         "HTTP/1.1 200 OK\r\n"
         "Content-Type: text/html; charset=utf-8\r\n"
         "Content-Length: %zu\r\n"
         "Connection: close\r\n\r\n", hlen);
     write(sock, header, hdrlen);
     write(sock, HTML, hlen);
 }
 
 /* Handshake */
 static int ws_handshake(int sock, char *buf) {
     char *ks = strstr(buf, "Sec-WebSocket-Key:");
     if(!ks) {
         serve_html(sock);
         return -1;
     }
     ks += 18;
     while(*ks==' ') ks++;
     char key[128]={0};
     int i=0;
     while(ks[i]!='\r'&&ks[i]!='\n'&&i<127){key[i]=ks[i];i++;}
     key[i]='\0';
 
     char combined[256];
     snprintf(combined,sizeof(combined),"%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",key);
     uint8_t digest[20];
     sha1((const uint8_t*)combined, strlen(combined), digest);
     char *accept = b64enc(digest, 20);
 
     char resp[512];
     int rlen = snprintf(resp,sizeof(resp),
         "HTTP/1.1 101 Switching Protocols\r\n"
         "Upgrade: websocket\r\n"
         "Connection: Upgrade\r\n"
         "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
     free(accept);
     int sent = write(sock, resp, rlen);
     return (sent > 0) ? 0 : -1;
 }
 
 /* Wysylanie */
 static int ws_send(int sock, const char *msg, size_t len) {
     unsigned char *frame = malloc(len + 10);
     if(!frame) return -1;
     int hl;
     frame[0]=0x81;
     if(len<=125){frame[1]=(unsigned char)len;hl=2;}
     else{frame[1]=126;frame[2]=(len>>8)&0xFF;frame[3]=len&0xFF;hl=4;}
     memcpy(frame+hl,msg,len);
     int r=write(sock,frame,hl+len);
     free(frame);
     return r;
 }
 
 /* Odbior */
 static int ws_recv(int sock, char *out, size_t out_size) {
     unsigned char hdr[2];
     if(recv(sock,hdr,2,MSG_WAITALL)!=2) return -1;
     int opcode=hdr[0]&0x0F;
     if(opcode==0x8) return 0;
     int masked=(hdr[1]>>7)&1;
     size_t payload=hdr[1]&0x7F;
     if(payload==126){
         unsigned char ext[2];
         if(recv(sock,ext,2,MSG_WAITALL)!=2) return -1;
         payload=(ext[0]<<8)|ext[1];
     } else if(payload==127) return -1;
     unsigned char mask[4]={0};
     if(masked && recv(sock,mask,4,MSG_WAITALL)!=4) return -1;
     if(payload>=out_size) return -1;
     if(recv(sock,out,payload,MSG_WAITALL)!=(ssize_t)payload) return -1;
     if(masked) for(size_t k=0;k<payload;k++) out[k]^=mask[k%4];
     out[payload]='\0';
     return (int)payload;
 }
 
 /* Broadcast */
 static void broadcast(int sender, const char *msg, size_t len) {
     pthread_mutex_lock(&clients_mutex);
     for(int i=0;i<client_count;i++)
         if(clients[i]!=sender) ws_send(clients[i],msg,len);
     pthread_mutex_unlock(&clients_mutex);
 }
 
 /* Klienci */
 static void client_add(int sock){
     pthread_mutex_lock(&clients_mutex);
     if(client_count<MAX_CLIENTS) clients[client_count++]=sock;
     pthread_mutex_unlock(&clients_mutex);
 }
 static void client_remove(int sock){
     pthread_mutex_lock(&clients_mutex);
     for(int i=0;i<client_count;i++)
         if(clients[i]==sock){clients[i]=clients[--client_count];break;}
     pthread_mutex_unlock(&clients_mutex);
 }
 
 /* Edycja */
 static int apply_edit(int pos, int del, const char *ins, int ins_len){
     if(pos<0||pos>doc_len) return -1;
     if(pos+del>doc_len) del=doc_len-pos;
     if(doc_len-del+ins_len>=MAX_DOC_SIZE) return -1;
     memmove(document+pos+ins_len, document+pos+del, doc_len-pos-del);
     memcpy(document+pos, ins, ins_len);
     doc_len=doc_len-del+ins_len;
     document[doc_len]='\0';
     sequence_id++;
     return 0;
 }
 
 /* Klient */
 static void *connection_handler(void *arg){
     int sock=*(int*)arg;
     free(arg);
 
     /* HTTP */
     char buf[4096]={0};
     int n=recv(sock,buf,sizeof(buf)-1,0);
     if(n<=0){close(sock);pthread_exit(NULL);}
 
     /* Protokol */
     if(ws_handshake(sock, buf)!=0){
         /* Zamkniecie */
         close(sock);
         pthread_exit(NULL);
     }
 
     /* WebSocket */
     client_add(sock);
     fprintf(stderr,"[+] Klient fd=%d połączony. Aktywni: %d\n",sock,client_count);
 
     /* Inicjalizacja */
     pthread_mutex_lock(&doc_mutex);
     json_escape(document, g_esc, sizeof(g_esc));
     int mlen=snprintf(g_msg,sizeof(g_msg),
         "{\"type\":\"init\",\"seq\":%lu,\"content\":\"%s\"}",sequence_id,g_esc);
     char *init_msg=malloc(mlen+1);
     memcpy(init_msg,g_msg,mlen+1);
     pthread_mutex_unlock(&doc_mutex);
     ws_send(sock,init_msg,mlen);
     free(init_msg);
 
     /* Odbior */
     char *frame=malloc(FRAME_BUF_SIZE);
     int r;
     while((r=ws_recv(sock,frame,FRAME_BUF_SIZE))>0){
         char type[32];
         json_str(frame,"type",type,sizeof(type));
         if(strcmp(type,"edit")!=0) continue;
         int pos=json_int(frame,"pos");
         int del=json_int(frame,"del");
         char *ins=malloc(FRAME_BUF_SIZE);
         int ins_len=json_str(frame,"ins",ins,FRAME_BUF_SIZE);
         if(pos<0)pos=0;
         if(del<0)del=0;
 
         pthread_mutex_lock(&doc_mutex);
         int ok=apply_edit(pos,del,ins,ins_len);
         unsigned long seq=sequence_id;
         json_escape(document,g_esc,sizeof(g_esc));
         int olen=snprintf(g_msg,sizeof(g_msg),
             "{\"type\":\"update\",\"seq\":%lu,\"pos\":%d,\"del\":%d,"
             "\"ins\":\"%s\",\"content\":\"%s\"}",
             seq,pos,del,ins,g_esc);
         char *out_msg=malloc(olen+1);
         memcpy(out_msg,g_msg,olen+1);
         pthread_mutex_unlock(&doc_mutex);
 
         free(ins);
         if(ok==0){
             ws_send(sock,out_msg,olen);
             broadcast(sock,out_msg,olen);
         }
         free(out_msg);
     }
 
     free(frame);
     client_remove(sock);
     close(sock);
     fprintf(stderr,"[-] Klient fd=%d rozłączony. Aktywni: %d\n",sock,client_count);
     pthread_exit(NULL);
 }
 
 /* Main */
 int main(void){
     signal(SIGPIPE,SIG_IGN);
     int lfd=socket(AF_INET,SOCK_STREAM,0);
     if(lfd<0){perror("socket");return 1;}
     int opt=1;
     setsockopt(lfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
     struct sockaddr_in addr;
     memset(&addr,0,sizeof(addr));
     addr.sin_family=AF_INET;
     addr.sin_addr.s_addr=htonl(INADDR_ANY);
     addr.sin_port=htons(PORT);
     if(bind(lfd,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind");return 1;}
     listen(lfd,10);
     fprintf(stderr,"Serwer nasłuchuje na porcie %d...\n",PORT);
     for(;;){
         int cfd=accept(lfd,NULL,NULL);
         if(cfd<0){perror("accept");continue;}
         int *a=malloc(sizeof(int)); *a=cfd;
         pthread_t tid;
         if(pthread_create(&tid,NULL,connection_handler,a)!=0){free(a);close(cfd);}
         else pthread_detach(tid);
     }
 }