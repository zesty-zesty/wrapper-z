#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include "import.h"
#include "cmdline.h"
#include "cjson/cjson.h"
#include "thread_pool.h"

// Portable compatibility for non-Linux platforms
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

static inline int is_transient_accept_errno(int e) {
#ifdef ENETDOWN
    if (e == ENETDOWN) return 1;
#endif
#ifdef EPROTO
    if (e == EPROTO) return 1;
#endif
#ifdef ENOPROTOOPT
    if (e == ENOPROTOOPT) return 1;
#endif
#ifdef EHOSTDOWN
    if (e == EHOSTDOWN) return 1;
#endif
#ifdef ENONET
    if (e == ENONET) return 1;
#endif
#ifdef EHOSTUNREACH
    if (e == EHOSTUNREACH) return 1;
#endif
#ifdef EOPNOTSUPP
    if (e == EOPNOTSUPP) return 1;
#endif
#ifdef ENETUNREACH
    if (e == ENETUNREACH) return 1;
#endif
    return 0;
}

static int accept4_compat(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
#if defined(__linux__)
    return accept4(fd, addr, addrlen, flags);
#else
    int cfd = accept(fd, addr, addrlen);
    if (cfd >= 0 && (flags & SOCK_CLOEXEC)) {
#ifdef FD_CLOEXEC
        (void)fcntl(cfd, F_SETFD, FD_CLOEXEC);
#endif
    }
    return cfd;
#endif
}

static struct shared_ptr apInf;
static uint8_t leaseMgr[16];
struct gengetopt_args_info args_info;
char *amUsername, *amPassword;
struct shared_ptr GUID;

int file_exists(char *filename) {
  struct stat buffer;   
  return (stat (filename, &buffer) == 0);
}

char *strcat_b(char *dest, char* src) {
    size_t len1 = strlen(dest);
    size_t len2 = strlen(src);

    char *result = malloc(len1 + len2 + 1);
    if (!result) return NULL; 

    strcpy(result, dest);
    strcat(result, src);

    return result;
}

static void dialogHandler(long j, struct shared_ptr *protoDialogPtr,
                          struct shared_ptr *respHandler) {
    const char *const title = std_string_data(
        _ZNK17storeservicescore14ProtocolDialog5titleEv(protoDialogPtr->obj));
    fprintf(stderr, "[.] dialogHandler: {title: %s, message: %s}\n", title,
            std_string_data(_ZNK17storeservicescore14ProtocolDialog7messageEv(
                protoDialogPtr->obj)));

    unsigned char ptr[72];
    memset(ptr + 8, 0, 16);
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN17storeservicescore22ProtocolDialogResponseENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr diagResp = {.obj = ptr + 24, .ctrl_blk = ptr};
    _ZN17storeservicescore22ProtocolDialogResponseC1Ev(diagResp.obj);

    struct std_vector *butVec =
        _ZNK17storeservicescore14ProtocolDialog7buttonsEv(protoDialogPtr->obj);
    if (strcmp("Sign In", title) == 0) {
        for (struct shared_ptr *b = butVec->begin; b != butVec->end; ++b) {
            if (strcmp("Use Existing Apple ID",
                       std_string_data(
                           _ZNK17storeservicescore14ProtocolButton5titleEv(
                               b->obj))) == 0) {
                _ZN17storeservicescore22ProtocolDialogResponse17setSelectedButtonERKNSt6__ndk110shared_ptrINS_14ProtocolButtonEEE(
                    diagResp.obj, b);
                break;
            }
        }
    } else {
        for (struct shared_ptr *b = butVec->begin; b != butVec->end; ++b) {
            fprintf(
                stderr, "[.] button %p: %s\n", b->obj,
                std_string_data(
                    _ZNK17storeservicescore14ProtocolButton5titleEv(b->obj)));
        }
    }
    _ZN20androidstoreservices28AndroidPresentationInterface28handleProtocolDialogResponseERKlRKNSt6__ndk110shared_ptrIN17storeservicescore22ProtocolDialogResponseEEE(
        apInf.obj, &j, &diagResp);
}

static void credentialHandler(struct shared_ptr *credReqHandler,
                              struct shared_ptr *credRespHandler) {
    const uint8_t need2FA =
        _ZNK17storeservicescore18CredentialsRequest28requiresHSA2VerificationCodeEv(
            credReqHandler->obj);
    fprintf(
        stderr, "[.] credentialHandler: {title: %s, message: %s, 2FA: %s}\n",
        std_string_data(_ZNK17storeservicescore18CredentialsRequest5titleEv(
            credReqHandler->obj)),
        std_string_data(_ZNK17storeservicescore18CredentialsRequest7messageEv(
            credReqHandler->obj)),
        need2FA ? "true" : "false");

    size_t passLen = amPassword ? strlen(amPassword) : 0;

    if (need2FA) {
        char code_buf[16] = {0};
        FILE *in = stdin;
        if (!in || !isatty(fileno(in))) {
            in = fopen("/dev/tty", "r");
        }
        fprintf(stderr, "2FA code: ");
        fflush(stderr);
        if (in && fgets(code_buf, sizeof(code_buf), in) != NULL) {
            size_t n = strcspn(code_buf, "\r\n");
            code_buf[n] = '\0';
            if (strlen(code_buf) > 6) {
                code_buf[6] = '\0';
            }
            size_t codeLen = strlen(code_buf);
            if (codeLen == 0) {
                fprintf(stderr, "[!] Empty 2FA code.\n");
                exit(EXIT_FAILURE);
            }
            char *combined = (char *)malloc(passLen + codeLen + 1);
            if (!combined) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            if (amPassword && passLen > 0) memcpy(combined, amPassword, passLen);
            memcpy(combined + passLen, code_buf, codeLen);
            combined[passLen + codeLen] = '\0';
            amPassword = combined;
            if (in != stdin) fclose(in);
        } else {
            fprintf(stderr, "[!] Failed to read 2FA code from input.\n");
            if (in && in != stdin) fclose(in);
            exit(EXIT_FAILURE);
        }
    }

    uint8_t *const ptr = malloc(80);
    memset(ptr + 8, 0, 16);
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN17storeservicescore19CredentialsResponseENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr credResp = {.obj = ptr + 24, .ctrl_blk = ptr};
    _ZN17storeservicescore19CredentialsResponseC1Ev(credResp.obj);

    union std_string username = new_std_string(amUsername);
    _ZN17storeservicescore19CredentialsResponse11setUserNameERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        credResp.obj, &username);

    union std_string password = new_std_string(amPassword);
    _ZN17storeservicescore19CredentialsResponse11setPasswordERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        credResp.obj, &password);

    _ZN17storeservicescore19CredentialsResponse15setResponseTypeENS0_12ResponseTypeE(
        credResp.obj, 2);

    _ZN20androidstoreservices28AndroidPresentationInterface25handleCredentialsResponseERKNSt6__ndk110shared_ptrIN17storeservicescore19CredentialsResponseEEE(
        apInf.obj, &credResp);
}

#ifndef MyRelease
static uint8_t allDebug() { return 1; }
#endif

static inline void init() {
    // srand(time(0));

    // raise(SIGSTOP);
    fprintf(stderr, "[+] starting...\n");
    setenv("ANDROID_DNS_MODE", "local", 1);
    if (args_info.proxy_given) {
        fprintf(stderr, "[+] Using proxy %s\n", args_info.proxy_arg);
        setenv("all_proxy", args_info.proxy_arg, 1);
    }

    static const char *resolvers[2] = {"223.5.5.5", "223.6.6.6"};
    _resolv_set_nameservers_for_net(0, resolvers, 2, ".");
    // Debug hook disabled on this platform; proceeding without subhook.

    // static char android_id[16];
    // for (int i = 0; i < 16; ++i) {
    //     android_id[i] = "0123456789abcdef"[rand() % 16];
    // }
    union std_string conf1 = new_std_string(android_id);
    union std_string conf2 = new_std_string("");
    _ZN14FootHillConfig6configERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE(
        &conf1);

    // union std_string root = new_std_string("/");
    // union std_string natLib = new_std_string("/system/lib64/");
    // void *foothill = malloc(120);
    // _ZN8FootHillC2ERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_(
    //     foothill, &root, &natLib);
    // _ZN8FootHill24defaultContextIdentifierEv(foothill);

    _ZN17storeservicescore10DeviceGUID8instanceEvASM(&GUID);

    static uint8_t ret[88];
    static unsigned int conf3 = 29;
    static uint8_t conf4 = 1;
    _ZN17storeservicescore10DeviceGUID9configureERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_RKjRKbASM(
        &ret, GUID.obj, &conf1, &conf2, &conf3, &conf4);
}

static inline struct shared_ptr init_ctx() {
    fprintf(stderr, "[+] initializing ctx...\n");

    struct shared_ptr *reqCtx = newRequestContext(strcat_b(args_info.base_dir_arg, "/mpl_db"));
    struct shared_ptr *reqCtxCfg = getRequestContextConfig();

    prepareRequestContextConfig(reqCtxCfg);
    configureRequestContext(reqCtx);

    static uint8_t buf[88];
    initRequestContext(buf, reqCtx, reqCtxCfg);
    setFairPlayDirectoryPath(reqCtx, args_info.base_dir_arg);
    initPresentationInterface(&apInf, &dialogHandler, &credentialHandler);
    setPresentationInterface(reqCtx, &apInf);

    return *reqCtx;
}

extern void *endLeaseCallback;
extern void *pbErrCallback;

inline static uint8_t login(struct shared_ptr reqCtx) {
    fprintf(stderr, "[+] logging in...\n");
    if (file_exists(strcat_b(args_info.base_dir_arg, "/STOREFRONT_ID"))) {
        remove(strcat_b(args_info.base_dir_arg, "/STOREFRONT_ID"));
    }
    if (file_exists(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"))) {
        remove(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"));
    }
    struct shared_ptr flow;
    _ZNSt6__ndk110shared_ptrIN17storeservicescore16AuthenticateFlowEE11make_sharedIJRNS0_INS1_14RequestContextEEEEEES3_DpOT_ASM(
        &flow, &reqCtx);
    _ZN17storeservicescore16AuthenticateFlow3runEv(flow.obj);
    struct shared_ptr *resp =
        _ZNK17storeservicescore16AuthenticateFlow8responseEv(flow.obj);
    if (resp == NULL || resp->obj == NULL)
        return 0;
    const int respType =
        _ZNK17storeservicescore20AuthenticateResponse12responseTypeEv(
            resp->obj);
    fprintf(stderr, "[.] response type %d\n", respType);
    return respType == 6;
    // struct shared_ptr subStatMgr;
    // _ZN20androidstoreservices30SVSubscriptionStatusMgrFactory6createEv(&subStatMgr);
    // struct shared_ptr data;
    // int method = 2;
    // _ZN20androidstoreservices27SVSubscriptionStatusMgrImpl33checkSubscriptionStatusFromSourceERKNSt6__ndk110shared_ptrIN17storeservicescore14RequestContextEEERKNS_23SVSubscriptionStatusMgr26SVSubscriptionStatusSourceE(&data,
    // subStatMgr.obj, &reqCtx, &method);
    // return 1;
}

static inline uint8_t readfull(const int connfd, void *const buf,
                               const size_t size) {
    size_t red = 0;
    while (size > red) {
        const ssize_t b = read(connfd, ((uint8_t *)buf) + red, size - red);
        if (b <= 0)
            return 0;
        red += b;
    }
    return 1;
}

static inline void writefull(const int connfd, void *const buf,
                             const size_t size) {
    size_t red = 0;
    while (size > red) {
        const ssize_t b = write(connfd, ((uint8_t *)buf) + red, size - red);
        if (b <= 0) {
            perror("write");
            break;
        }
        red += b;
    }
}

static void *FHinstance = NULL;
static void *preshareCtx = NULL;
static pthread_mutex_t preshare_mutex = PTHREAD_MUTEX_INITIALIZER;

inline static void *getKdContext(const char *const adam,
                                 const char *const uri) {
    uint8_t isPreshare = (strcmp("0", adam) == 0);
    if (isPreshare) {
        pthread_mutex_lock(&preshare_mutex);
        if (preshareCtx != NULL) {
            void *cached = preshareCtx;
            pthread_mutex_unlock(&preshare_mutex);
            return cached;
        }
        pthread_mutex_unlock(&preshare_mutex);
    }
    fprintf(stderr, "[.] adamId: %s, uri: %s\n", adam, uri);

    union std_string defaultId = new_std_string(adam);
    union std_string keyUri = new_std_string(uri);
    union std_string keyFormat =
        new_std_string("com.apple.streamingkeydelivery");
    union std_string keyFormatVer = new_std_string("1");
    union std_string serverUri = new_std_string(
        "https://play.itunes.apple.com/WebObjects/MZPlay.woa/music/fps");
    union std_string protocolType = new_std_string("simplified");
    union std_string fpsCert = new_std_string(fairplay_cert);

    struct shared_ptr persistK = {.obj = NULL};
    _ZN21SVFootHillSessionCtrl16getPersistentKeyERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_S8_S8_S8_S8_S8_S8_ASM(
        &persistK, FHinstance, &defaultId, &defaultId, &keyUri, &keyFormat,
        &keyFormatVer, &serverUri, &protocolType, &fpsCert);

    if (persistK.obj == NULL)
        return NULL;

    struct shared_ptr SVFootHillPContext;
    _ZN21SVFootHillSessionCtrl14decryptContextERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEERKN11SVDecryptor15SVDecryptorTypeERKbASM(
        &SVFootHillPContext, FHinstance, persistK.obj);

    if (SVFootHillPContext.obj == NULL)
        return NULL;

    void *kdContext =
        *_ZNK18SVFootHillPContext9kdContextEv(SVFootHillPContext.obj);
    if (kdContext != NULL && isPreshare) {
        pthread_mutex_lock(&preshare_mutex);
        preshareCtx = kdContext;
        pthread_mutex_unlock(&preshare_mutex);
    }
    return kdContext;
}

void handle(const int connfd) {
    while (1) {
        uint8_t adamSize;
        if (!readfull(connfd, &adamSize, sizeof(uint8_t)))
            return;
        if (adamSize <= 0)
            return;

        char adam[adamSize + 1];
        if (!readfull(connfd, adam, adamSize))
            return;
        adam[adamSize] = '\0';

        uint8_t uri_size;
        if (!readfull(connfd, &uri_size, sizeof(uint8_t)))
            return;

        char uri[uri_size + 1];
        if (!readfull(connfd, uri, uri_size))
            return;
        uri[uri_size] = '\0';

        void **const kdContext = getKdContext(adam, uri);
        if (kdContext == NULL)
            return;

        while (1) {
            uint32_t size;
            if (!readfull(connfd, &size, sizeof(uint32_t))) {
                perror("read");
                return;
            }

            if (size <= 0)
                break;

            void *sample = malloc(size);
            if (sample == NULL) {
                perror("malloc");
                return;
            }
            if (!readfull(connfd, sample, size)) {
                free(sample);
                perror("read");
                return;
            }

            NfcRKVnxuKZy04KWbdFu71Ou(*kdContext, 5, sample, sample, size);
            writefull(connfd, sample, size);
            free(sample);
        }
    }
}

extern uint8_t handle_cpp(int);
void handle_m3u8(const int connfd);

typedef struct { int fd; } decrypt_conn_args;
static void decrypt_conn(void *arg) {
    decrypt_conn_args *a = (decrypt_conn_args *)arg;
    int cfd = a->fd;
    free(a);
    if (!handle_cpp(cfd)) {
        uint8_t autom = 1;
        _ZN22SVPlaybackLeaseManager12requestLeaseERKb(leaseMgr, &autom);
    }
    if (close(cfd) == -1) {
        perror("close");
    }
}

typedef struct { int fd; } m3u8_conn_args;
static void m3u8_conn(void *arg) {
    m3u8_conn_args *a = (m3u8_conn_args *)arg;
    int cfd = a->fd;
    free(a);
    handle_m3u8(cfd);
    if (close(cfd) == -1) {
        perror("close");
    }
}

inline static int new_socket(thread_pool_t *pool) {
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }
    const int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    static struct sockaddr_in serv_addr = {.sin_family = AF_INET};
    inet_pton(AF_INET, args_info.host_arg, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(args_info.decrypt_port_arg);
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind");
        return EXIT_FAILURE;
    }

    if (listen(fd, 5) == -1) {
        perror("listen");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[!] listening %s:%d\n", args_info.host_arg, args_info.decrypt_port_arg);
    // close(STDOUT_FILENO);

    static struct sockaddr_in peer_addr;
    static socklen_t peer_addr_size = sizeof(peer_addr);
    while (1) {
        const int connfd = accept4_compat(fd, (struct sockaddr *)&peer_addr,
                                   &peer_addr_size, SOCK_CLOEXEC);
        if (connfd == -1) {
            if (is_transient_accept_errno(errno))
                continue;
            perror("accept");
            return EXIT_FAILURE;
        }

        decrypt_conn_args *args = (decrypt_conn_args *)malloc(sizeof(decrypt_conn_args));
        if (args == NULL) {
            perror("malloc");
            close(connfd);
            continue;
        }
        args->fd = connfd;
        thread_pool_add(pool, decrypt_conn, args);
    }
}


const char* get_m3u8_method_play(uint8_t leaseMgr[16], unsigned long adam) {
    union std_string HLS = new_std_string_short_mode("HLS");
    struct std_vector HLSParam = new_std_vector(&HLS);
    static uint8_t z0 = 0;
    struct shared_ptr ptr_result;
    _ZN22SVPlaybackLeaseManager12requestAssetERKmRKNSt6__ndk16vectorINS2_12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEENS7_IS9_EEEERKbASM(
        &ptr_result, leaseMgr, &adam, &HLSParam, &z0
    );
    
    if (ptr_result.obj == NULL) {
        return NULL;
    }

    if (_ZNK23SVPlaybackAssetResponse13hasValidAssetEv(ptr_result.obj)) {
        struct shared_ptr *playbackAsset = _ZNK23SVPlaybackAssetResponse13playbackAssetEv(ptr_result.obj);
        if (playbackAsset == NULL || playbackAsset->obj == NULL) {
            return NULL;
        }

        union std_string *m3u8 = malloc(sizeof(union std_string));
        if (m3u8 == NULL) {
            return NULL;
        }

        void *playbackObj = playbackAsset->obj;
        _ZNK17storeservicescore13PlaybackAsset9URLStringEvASM(m3u8, playbackObj);

        if (m3u8 == NULL || std_string_data(m3u8) == NULL) {
            free(m3u8);
            return NULL;
        }
        
        const char *m3u8_str = std_string_data(m3u8);
        if (m3u8_str) {
            char *result = strdup(m3u8_str);  // Make a copy
            free(m3u8);
            return result;
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }
}

void handle_m3u8(const int connfd) {
    while (1)
    {
        uint8_t adamSize;
        if (!readfull(connfd, &adamSize, sizeof(uint8_t))) {
            return;
        }
        if (adamSize <= 0) {
            return;
        }
        char adam[adamSize];
        for (int i=0; i<adamSize; i=i+1) {
            readfull(connfd, &adam[i], sizeof(uint8_t));
        }
        char *ptr;
        unsigned long adamID = strtoul(adam, &ptr, 10);
        const char *m3u8 = get_m3u8_method_play(leaseMgr, adamID);
        if (m3u8 == NULL) {
            fprintf(stderr, "[.] failed to get m3u8 of adamId: %ld\n", adamID);
            writefull(connfd, "\n", sizeof("\n"));
        } else {
            fprintf(stderr, "[.] m3u8 adamId: %ld, url: %s\n", adamID, m3u8);
            char *with_newline = malloc(strlen(m3u8) + 2);
            if (with_newline) {
                strcpy(with_newline, m3u8);
                strcat(with_newline, "\n");
                writefull(connfd, with_newline, strlen(with_newline));
                free(with_newline);
            }
            free((void *)m3u8);
        }
    }
}

static inline void *new_socket_m3u8(void *pool_ptr) {
    thread_pool_t *pool = (thread_pool_t *)pool_ptr;
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd == -1) {
        perror("socket");
        return NULL;
    }
    const int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    static struct sockaddr_in serv_addr = {.sin_family = AF_INET};
    inet_pton(AF_INET, args_info.host_arg, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(args_info.m3u8_port_arg);
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind");
    }

    if (listen(fd, 5) == -1) {
        perror("listen");
    }

    fprintf(stderr, "[!] listening m3u8 request on %s:%d\n", args_info.host_arg, args_info.m3u8_port_arg);
    // close(STDOUT_FILENO);

    static struct sockaddr_in peer_addr;
    static socklen_t peer_addr_size = sizeof(peer_addr);
    while (1) {
        const int connfd = accept4_compat(fd, (struct sockaddr *)&peer_addr,
                                   &peer_addr_size, SOCK_CLOEXEC);
        if (connfd == -1) {
            if (is_transient_accept_errno(errno))
                continue;
            perror("accept");
            
        }

        m3u8_conn_args *args_m = (m3u8_conn_args *)malloc(sizeof(m3u8_conn_args));
        if (args_m == NULL) {
            perror("malloc");
            close(connfd);
            continue;
        }
        args_m->fd = connfd;
        thread_pool_add(pool, m3u8_conn, args_m);
    }
}

char* get_account_storefront_id(struct shared_ptr reqCtx) {
    union std_string *region = malloc(sizeof(union std_string));
    struct shared_ptr urlbag = {.obj = 0x0, .ctrl_blk = 0x0};
    _ZNK17storeservicescore14RequestContext20storeFrontIdentifierERKNSt6__ndk110shared_ptrINS_6URLBagEEEASM(region, reqCtx.obj, &urlbag);
    const char *region_str = std_string_data(region);
    if (region_str) {
        char *result = strdup(region_str); 
        free(region);
        return result;
    } 
    return NULL;
}

void write_storefront_id(struct shared_ptr reqCtx) {
    FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/STOREFRONT_ID"), "w");
    char *storefront_id = get_account_storefront_id(reqCtx);
    printf("[+] StoreFront ID: %s\n", storefront_id);
    fprintf(fp, "%s", get_account_storefront_id(reqCtx));
    fclose(fp);
}

char *get_guid() {
    char *ret[2];
    _ZN17storeservicescore10DeviceGUID4guidEvASM(ret, GUID.obj);
    char *guid = _ZNK13mediaplatform4Data5bytesEv(ret[0]);
    return guid;
}

long long getCurrentTimeMillis() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}


char *get_music_user_token(char *guid, char *authToken, struct shared_ptr reqCtx){
    uint8_t ptr[480];
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN13mediaplatform11HTTPMessageENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr httpMessage = {.obj = ptr + 32, .ctrl_blk = ptr};
    union std_string url = new_std_string("https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/createMusicToken");
    union std_string method = new_std_string("POST");
    _ZN13mediaplatform11HTTPMessageC2ENSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_(httpMessage.obj, &url, &method);
    union std_string contentTypeHeader = new_std_string("Content-Type");
    union std_string contentTypeValue = new_std_string("application/json; charset=UTF-8");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &contentTypeHeader, &contentTypeValue);
    union std_string expectHeader = new_std_string("Expect");
    union std_string expectValue = new_std_string("");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &expectHeader, &expectValue);
    union std_string bundleIdHeader = new_std_string("X-Apple-Requesting-Bundle-Id");
    union std_string bundleIdValue = new_std_string("com.apple.android.music");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &bundleIdHeader, &bundleIdValue);
    union std_string bundleVersionHeader = new_std_string("X-Apple-Requesting-Bundle-Version");
    union std_string bundleVersionValue = new_std_string("Music/4.9 Android/10 model/Samsung S9 build/7663313 (dt:66)");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &bundleVersionHeader, &bundleVersionValue);
    size_t body_size = 512;
    char *body = (char *)malloc(body_size);
    if (body == NULL) {
        return "";
    }

    snprintf(body, body_size, "{\"guid\":\"%s\",\"assertion\":\"%s\",\"tcc-acceptance-date\":\"%lld\"}", guid, authToken, getCurrentTimeMillis());

    _ZN13mediaplatform11HTTPMessage11setBodyDataEPcm(httpMessage.obj, body, strlen(body));
    free(body);
    uint8_t urlRequest[512];
    _ZN17storeservicescore10URLRequestC2ERKNSt6__ndk110shared_ptrIN13mediaplatform11HTTPMessageEEERKNS2_INS_14RequestContextEEE(urlRequest, &httpMessage, &reqCtx);
    _ZN17storeservicescore10URLRequest3runEv(urlRequest);
    struct shared_ptr *err = _ZNK17storeservicescore10URLRequest5errorEv(urlRequest);
    if (err->obj != NULL) {
        return "";
    }
    struct shared_ptr *urlResp = _ZNK17storeservicescore10URLRequest8responseEv(urlRequest);
    struct shared_ptr *resp = _ZNK17storeservicescore11URLResponse18underlyingResponseEv(urlResp->obj);
    void *http_message_obj = resp->obj;
    void** data_ptr_location = (void**)((char*)http_message_obj + 48);
    void* data_ptr = *data_ptr_location;
    char *respBody = _ZNK13mediaplatform4Data5bytesEv(data_ptr);
    cJSON *json = cJSON_Parse(respBody);
    cJSON *token_obj = cJSON_GetObjectItemCaseSensitive(json, "music_token");
    char *token = cJSON_GetStringValue(token_obj);
    char *result = strdup(token);
    return result;
}


char* get_dev_token(struct shared_ptr reqCtx) {
    uint8_t ptr[480];
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN13mediaplatform11HTTPMessageENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr httpMessage = {.obj = ptr + 32, .ctrl_blk = ptr};
    union std_string url = new_std_string("https://sf-api-token-service.itunes.apple.com/apiToken");
    union std_string method = new_std_string("GET");
    _ZN13mediaplatform11HTTPMessageC2ENSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_(httpMessage.obj, &url, &method);
    uint8_t urlRequest[512];
    _ZN17storeservicescore10URLRequestC2ERKNSt6__ndk110shared_ptrIN13mediaplatform11HTTPMessageEEERKNS2_INS_14RequestContextEEE(urlRequest, &httpMessage, &reqCtx);
    union std_string clientIdName = new_std_string("clientId");
    union std_string clientIdValue = new_std_string("musicAndroid");
    _ZN17storeservicescore10URLRequest19setRequestParameterERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(urlRequest, &clientIdName, &clientIdValue);
    union std_string versionName = new_std_string("version");
    union std_string versionValue = new_std_string("1");
    _ZN17storeservicescore10URLRequest19setRequestParameterERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(urlRequest, &versionName, &versionValue);
    _ZN17storeservicescore10URLRequest3runEv(urlRequest);
    struct shared_ptr *err = _ZNK17storeservicescore10URLRequest5errorEv(urlRequest);
    if (err->obj != NULL) {
        return "";
    }
    struct shared_ptr *urlResp = _ZNK17storeservicescore10URLRequest8responseEv(urlRequest);
    struct shared_ptr *resp = _ZNK17storeservicescore11URLResponse18underlyingResponseEv(urlResp->obj);
    void *http_message_obj = resp->obj;
    void** data_ptr_location = (void**)((char*)http_message_obj + 48);
    void* data_ptr = *data_ptr_location;
    char *respBody = _ZNK13mediaplatform4Data5bytesEv(data_ptr);
    cJSON *json = cJSON_Parse(respBody);
    cJSON *token_obj = cJSON_GetObjectItemCaseSensitive(json, "token");
    char *token = cJSON_GetStringValue(token_obj);
    char *result = strdup(token);
    return result;
}

void write_music_token(struct shared_ptr reqCtx) {
    int token_file_available = 0;
    if (file_exists(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"))) {
        FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"), "r");
        if (NULL != fp) {
            fseek (fp, 0, SEEK_END);
            long size = ftell(fp);

            if (0 != size) {
                token_file_available = 1;
            }
        }
    }
    if (token_file_available) {
        char token[256];
        FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"), "r");
        fgets(token, sizeof(token), fp);
        printf("[+] Music-Token: %.14s...\n", token);
        return;
    }
    FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"), "w");
    char *guid = get_guid();
    char *dev_token = get_dev_token(reqCtx);
    char *token = get_music_user_token(guid, dev_token, reqCtx);
    printf("[+] Music-Token: %.14s...\n", token);
    fprintf(fp, "%s", token);
    fclose(fp);
}

int main(int argc, char *argv[]) {
    cmdline_parser(argc, argv, &args_info);

    init();
    const struct shared_ptr ctx = init_ctx();
    if (args_info.login_given) {
        amUsername = strtok(args_info.login_arg, ":");
        amPassword = strtok(NULL, ":");
    }
    if (args_info.login_given && !login(ctx)) {
        fprintf(stderr, "[!] login failed\n");
        return EXIT_FAILURE;
    }
    _ZN22SVPlaybackLeaseManagerC2ERKNSt6__ndk18functionIFvRKiEEERKNS1_IFvRKNS0_10shared_ptrIN17storeservicescore19StoreErrorConditionEEEEEE(
        leaseMgr, &endLeaseCallback, &pbErrCallback);
    uint8_t autom = 1;
    _ZN22SVPlaybackLeaseManager25refreshLeaseAutomaticallyERKb(leaseMgr,
                                                               &autom);
    _ZN22SVPlaybackLeaseManager12requestLeaseERKb(leaseMgr, &autom);
    FHinstance = getFootHillInstance();

    write_storefront_id(ctx);
    write_music_token(ctx);

        thread_pool_t *pool = thread_pool_create(4, 64);

    pthread_t m3u8_thread;
    pthread_create(&m3u8_thread, NULL, new_socket_m3u8, pool);
    pthread_detach(m3u8_thread);

    new_socket(pool);

    thread_pool_destroy(pool);

    return 0;
}