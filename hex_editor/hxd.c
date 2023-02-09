#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define VERSION         ("0.0.1")
#define QUIT_TIMES      (3)
#define CTRL_KEY(k)     ((k) & 0x1f)
#define ROW_LEN         (0x100) // must bigger than 67 = 8(addr) + 1(":") + 40(hex) + 2(gap) + 16(ascii) 
#define ADDR_LEN        (8)
#define BYTES_PER_ROW   (16)
#define GAP             (4)
#define HEX_START_POS   (ADDR_LEN + 1)
#define HEX_END_POS     (HEX_START_POS + BYTES_PER_ROW/2*5 - 1)
#define ASCII_START_POS (HEX_END_POS + GAP + 1)
#define ASCII_END_POS   (ASCII_START_POS + BYTES_PER_ROW - 1)

#define POSTIVE_INFINITY  (0xFFFFFFF)

typedef enum {
    // FIXME: other platform ?
    BACKSPACE = 8,
    ARROW_LEFT = 1000,
    ARROW_RIGHT,
    ARROW_UP,
    ARROW_DOWN,
    DEL_KEY,
    HOME_KEY,
    END_KEY,
    PAGE_UP,
    PAGE_DOWN
} editorKey;

typedef enum {
    ADDRESS,
    HEX,
    ASCII
} REGION;

struct editorConfiguration {
    char *filename;
    unsigned int screenRow;
    unsigned int screenCol;
    struct termios orig;
};

struct editorMetadata {
    char **text;
    unsigned int numRows;

    unsigned int x, y;

    char *statusMsg;
    time_t statusTime;

    // scroll
    unsigned int pageFirstRowIdx;
    unsigned int pageFirstColIdx;

    bool isDirty;
};

struct editor {
    struct editorConfiguration conf;
    struct editorMetadata metadata;
};

struct editor E;

void Log(const char *fmt, ...);
void closeLog();

void terminate(const int code);
void die(const char *s);
void enableRawMode();
void disableRawMode();

static inline int hexToInt(char c);
static inline char intToHex(int d);
static inline bool isPrintable(char c);
static void append(char **p, const char *s, unsigned int len);

static void initEditor();
static void editorSetStatusMessage(const char *fmt, ...);
static void editorRefreshScreen();
static void editorInsertRow(const unsigned int, const char *);
static void editorMoveCursor(int key);
static void editorSave();
static void editorScroll();
static void editorDrawRows(char **buf);
static void editorDrawMessageBar(char **buf);
static void editorRefreshScreen();
static void editorSetStatusMessage(const char *fmt, ...);
static void editorMoveCursor(int key);
static void editorProcessKeypress();
static int  editorReadKey();

static inline bool isValidPos(const unsigned int x, const unsigned int y);
static inline bool isFirstHex(const unsigned int x);
static inline bool isFirstByte(const unsigned int x, const unsigned int y);
static inline bool isLastByte(const unsigned int x, const unsigned int y);

static int getCursorPosition(unsigned int *rows, unsigned int *cols);
static int getWindowSize(unsigned int *rows, unsigned int *cols);
static inline REGION getRegion(const int x);
static inline REGION getCurRegion();
static inline char getNthRowByte(char *row, const unsigned int at);
static inline bool hasPrev(const unsigned int x, const unsigned int y);
static inline bool hasNext(const unsigned int x, const unsigned int y);
static inline int posToByteIdx(const int x);
static inline int getLastRowBytesNum();
static inline int nthBytePosInHexRegion(int n);
static inline int nthBytePosInASCIIRegion(int n);
static inline int getByteIdxInHexRegion(int x);
static inline int getByteIdxInASCIIRegion(int x);
static inline void backwardOne(unsigned int *x, unsigned int *y);
static inline void backwardCurOne();
static inline void backwardOneByte(unsigned int *x, unsigned int *y);
static inline void backwardCurOneByte();
static inline void forwardOne(unsigned int *x, unsigned int *y);
static inline void forwardCurOne();
static inline void forwardOneByte(unsigned int *x, unsigned int *y);
static inline void forwardCurOneByte();
static inline void setDirty();
static inline void setClean();
static void createRow(char *s, const int len);

FILE *logFptr;

void Log(const char *fmt, ...) {
    if (logFptr == NULL) {
        logFptr = fopen("./log", "a");
        if (logFptr == NULL)
            die("open log failed");
    }

    va_list args;
    va_start(args,     fmt);
    vfprintf(logFptr, fmt, args);
    va_end(args);
}

void closeLog() {
    if (logFptr) {
        fclose(logFptr);
    }
}

void terminate(const int code) {
    closeLog();
    exit(code);
}

void die(const char *s) {
    write(STDOUT_FILENO, "\x1b[2J", 4);
    write(STDOUT_FILENO, "\x1b[H", 3);

    perror(s);
    terminate(1);
}

void enableRawMode() {
    if (tcgetattr(STDIN_FILENO, &E.conf.orig) == -1)
        die("tcgetattr");

    atexit(disableRawMode);

    struct termios raw = E.conf.orig;
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1)
        die("tcsetattr");
}

void disableRawMode() {
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &E.conf.orig) == -1)
        die("tcsetattr");
}

static inline bool isValidPos(const unsigned int x, const unsigned int y) {
    // loosely check, at least not overflow
    return x <= ASCII_END_POS && y < E.metadata.numRows;
}

static inline bool isFirstHex(const unsigned int x) {
    if (getRegion(x) != HEX)
        return false;

    return (x - HEX_START_POS)%5%2;
}

static inline bool isFirstByte(const unsigned int x, const unsigned int y) {
    return E.metadata.numRows != 0 && getByteIdxInHexRegion(x) == 0 && y == 0;
}

static inline bool isLastByte(const unsigned int x, const unsigned int y) {
    return y == (E.metadata.numRows-1) && getByteIdxInHexRegion(x) == getLastRowBytesNum() - 1;
}

static inline int hexToInt(const char c) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        return 0;

    return c >= 'a' ? c - 'a' + 10 : c - '0';
}

static inline char intToHex(int d) {
    return d > 9 ? d%10 + 'a' : d + '0';
}

static inline REGION getRegion(const int x) {
    if (x < HEX_START_POS)
        return ADDRESS;
    
    if (x < ASCII_START_POS)
        return HEX;

    return ASCII;
}

static inline REGION getCurRegion() {
    return getRegion(E.metadata.x);
}

static inline int posToByteIdx(const int x) {
    int idx = (x - HEX_START_POS);
    return idx/5*2 + ((idx%5) - 1)/2;
}

static inline char getNthRowByte(char *row, const unsigned int at) {
    if (at > BYTES_PER_ROW)
        die("getNthRowByte: invalid");

    int pos = nthBytePosInHexRegion(at);
    if (row[pos] == ' ')
        return 0;

    int hi = hexToInt(row[pos]);
    int lo = hexToInt(row[pos + 1]);
    return hi*16 + lo;
}

static inline bool isPrintable(char c) {
    return  c >= 0x20 && c < 0x7f;
}

static inline bool hasNext(const unsigned int x, const unsigned int y) {
    return E.metadata.numRows != 0 && (y < E.metadata.numRows - 1 || x < strlen(E.metadata.text[y]) - 1);
}

static inline bool hasPrev(const unsigned int x, const unsigned int y) {
    return !(x == HEX_START_POS + 1 && y == 0);
}

static inline void forwardCurOne() {
    forwardOne(&E.metadata.x, &E.metadata.y);
}

static inline void forwardOne(unsigned int *x, unsigned int *y) {
    while (hasNext(*x, *y)) {
        if (*x == ASCII_END_POS) {
            *x = HEX_START_POS;
            ++(*y);
        }

        ++(*x);
        if (E.metadata.text[*y][*x] != ' ' || getRegion(*x) != HEX)
            break;
    }
}

static inline void forwardCurOneByte() {
    forwardOneByte(&E.metadata.x, &E.metadata.y);
}

static inline void forwardOneByte(unsigned int *x, unsigned int *y) {
    if (getRegion(*x) != HEX)
        die("forwardOneByte invalid");

    if (isLastByte(*x, *y))
        return;

    while (hasNext(*x, *y)) {
        forwardOne(x, y);
        if (isFirstHex(*x))
            break;
    }
}

static inline void backwardCurOne() {
    backwardOne(&E.metadata.x, &E.metadata.y);
}

static inline void backwardOne(unsigned int *x, unsigned int *y) {
    while (hasPrev(*x, *y)) {
        if (*x == HEX_START_POS) {
            *x = ASCII_END_POS;
            --(*y);
        }
    
        --(*x);
        if (E.metadata.text[*y][*x] != ' ' || getCurRegion() != HEX)
            break;
    }
}

static inline void backwardCurOneByte() {
    backwardOneByte(&E.metadata.x, &E.metadata.y);
}

static inline void backwardOneByte(unsigned int *x, unsigned int *y) {
    if (getRegion(*x) != HEX)
        die("backwardOneByte: invalid region");

    if (isFirstByte(*x, *y))
        return;

    while (hasPrev(*x, *y)) {
        backwardOne(x, y);
        if (isFirstHex(*x))
            break;
    }
}

static int editorReadKey() {
    int nread;
    char c;
    while ((nread = read(STDIN_FILENO, &c, 1)) != 1) {
        if (nread == -1 && errno != EAGAIN)
            die("read");
    }

    if (c == '\x1b') {
        char seq[3];

        if (read(STDIN_FILENO, &seq[0], 1) != 1) return '\x1b';
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return '\x1b';

        if (seq[0] == '[') {
            if (seq[1] >= '0' && seq[1] <= '9') {
                if (read(STDIN_FILENO, &seq[2], 1) != 1) return '\x1b';
                if (seq[2] == '~') {
                    switch (seq[1]) {
                        case '1': return HOME_KEY;
                        case '3': return DEL_KEY;
                        case '4': return END_KEY;
                        case '5': return PAGE_UP;
                        case '6': return PAGE_DOWN;
                        case '7': return HOME_KEY;
                        case '8': return END_KEY;
                    }
                }
            } else {
                switch (seq[1]) {
                    case 'A': return ARROW_UP;
                    case 'B': return ARROW_DOWN;
                    case 'C': return ARROW_RIGHT;
                    case 'D': return ARROW_LEFT;
                    case 'H': return HOME_KEY;
                    case 'F': return END_KEY;
               }
           }
        } else if (seq[0] == 'O') {
            switch (seq[1]) {
                case 'H': return HOME_KEY;
                case 'F': return END_KEY;
            }
        }
        return '\x1b';
    } else {
       return c;
    }
}

static int getCursorPosition(unsigned int *rows, unsigned int *cols) {
    char buf[32];
    unsigned int i = 0;

    if (write(STDOUT_FILENO, "\x1b[6n", 4) != 4) return -1;

    while (i < sizeof(buf) - 1) {
        if (read(STDIN_FILENO, &buf[i], 1) != 1) break;
        if (buf[i] == 'R') break;
        i++;
    }
    buf[i] = '\0';
    
    if (buf[0] != '\x1b' || buf[1] != '[')
        return -1;

    if (sscanf(&buf[2], "%u;%u", rows, cols) != 2)
        return -1;
 
    return -1;
}

static int getWindowSize(unsigned int *rows, unsigned int *cols) {
    struct winsize ws;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
        if (write(STDOUT_FILENO, "\x1b[999C\x1b[999B", 12) != 12) return -1;
        editorReadKey();
        return getCursorPosition(rows, cols);
    } else {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
        return 0;
    }
}

static inline int nthBytePosInHexRegion(int n) {
    if (n < 0 || n >= BYTES_PER_ROW)
        die("nthBytePosInHexRegion: invalid");

    return HEX_START_POS + n/2*5 + 1 + (n%2)*2;
}

static inline int nthBytePosInASCIIRegion(int n) {
    if (n < 0 || n >= BYTES_PER_ROW)
        die("nthBytePosInASCIIRegion: invalid");

    return ASCII_START_POS + n;
}

static inline int getByteIdxInHexRegion(int x) {
    if (getRegion(x) != HEX)
        die("getByteIdxInHexRegion invalid");
    
    return ((x - HEX_START_POS)/5)*2 + ((x - HEX_START_POS - 1)%5)/2;
}

static inline int getByteIdxInASCIIRegion(int x) {
    if (getRegion(x) != ASCII)
        die("getByteIdxInASCIIRegion invalid");
    
    return x - ASCII_START_POS;
}

static inline int getLastRowBytesNum() {
    return strlen(E.metadata.text[E.metadata.numRows-1]) - ASCII_START_POS;
}

static inline void setDirty() {
    E.metadata.isDirty = true;
}

static inline void setClean() {
    E.metadata.isDirty = false;
}

static void createRow(char *s, const int len) {
    char buf[ROW_LEN] = "";

    snprintf(buf, ROW_LEN, "%.8x:", E.metadata.numRows * BYTES_PER_ROW);

    for (int i = 0; i+1 < len; i+=2)
        snprintf(buf + strlen(buf), ROW_LEN - strlen(buf), " %02x%02x", (unsigned char)s[i], (unsigned char)s[i+1]);
    
    if (len%2)
        snprintf(buf + strlen(buf), ROW_LEN - strlen(buf), " %02x", (unsigned char)s[len-1]);

    int p = strlen(buf);
    while (p < ASCII_START_POS)
        buf[p++] = ' ';

    for (int i = 0; i < len && p < ROW_LEN; ++i, ++p) {
        if (!isPrintable(s[i])) {
            buf[p] = '.';
    } else {
            buf[p] = s[i];
    }
    }

    if (p < ROW_LEN)
        buf[p] = '\0';

    editorInsertRow(E.metadata.numRows, buf);
}

static void rowBackOne(char *row, int start) {
    // HEX Region
    for (int i = BYTES_PER_ROW - 2; i >= start; --i) {
    int s = nthBytePosInHexRegion(i);
        int d = nthBytePosInHexRegion(i+1);

    row[d]   = row[s];
    row[d+1] = row[s+1];
    }
    
    // ASCII Region
    for (int i = BYTES_PER_ROW - 2; i >= start; --i) {
        int s = nthBytePosInASCIIRegion(i);
        int d = nthBytePosInASCIIRegion(i+1);

        row[d] = row[s];
    }
}

static void rowForwardOne(char *row, int start) {
    // HEX Region
    for (int i = start; i < BYTES_PER_ROW - 1; ++i) {
        int s = nthBytePosInHexRegion(i+1);
        int d = nthBytePosInHexRegion(i);

        row[d]   = row[s];
        row[d+1] = row[s+1];
    }
    
    // ASCII Region
    for (int i = start; i < BYTES_PER_ROW - 1; ++i) {
        int s = nthBytePosInASCIIRegion(i+1);
        int d = nthBytePosInASCIIRegion(i);

        row[d] = row[s];
    }
}

void editorInsertRow(const unsigned int idx, const char *s) {
    if (idx > E.metadata.numRows)
        die("editorInsertRow: invalid");

    E.metadata.text = realloc(E.metadata.text, (E.metadata.numRows + 1) * sizeof(char *));
    if (E.metadata.text == NULL)
        die("realloc");

    if (E.metadata.numRows > 0) {
        for (unsigned int i = E.metadata.numRows-1; i >= idx; --i)
            E.metadata.text[i+1] = E.metadata.text[i];
    }

    char *new_row = calloc(1, ROW_LEN);
    if (new_row == NULL)
        die("calloc");
   
    memcpy(new_row, s, strlen(s));
    E.metadata.text[idx] = new_row;

    E.metadata.numRows++;
}

void editorRowEditChar(const unsigned int x, const unsigned int y, unsigned char c) {
    if (!isValidPos(x, y))
        die("editorRowEditChar: invalid position");
    
    char *row = E.metadata.text[y];

    row[x] = c;
    if (getRegion(x) == HEX) {
        int n = getByteIdxInHexRegion(x);
        int idx = nthBytePosInASCIIRegion(n);
        int val = getNthRowByte(row, n);
        row[idx] = isPrintable(val) ? val : '.';
    } else if (getRegion(x) == ASCII) {
        int   n = getByteIdxInASCIIRegion(x);
        int idx = nthBytePosInHexRegion(n);
        row[idx]   = intToHex(c/16);
        row[idx+1] = intToHex(c%16);
    } else {
        die("editorRowEditChar invalid region");
    }
}

void insertByte(const unsigned int x, const unsigned int y) {
    if (!isFirstHex(x))
        die("insertByte: invalid x position");

    char firstIdx = posToByteIdx(x);
    char firstByte = '\0';
    char lastByte = '\0';

    for (unsigned int i = y; i < E.metadata.numRows; ++i) {
        char *row = E.metadata.text[i];
        lastByte = getNthRowByte(row, BYTES_PER_ROW - 1);

        rowBackOne(row, firstIdx);
        row[nthBytePosInHexRegion(firstIdx)]   = intToHex(firstByte/16);
        row[nthBytePosInHexRegion(firstIdx)+1] = intToHex(firstByte%16);
        row[nthBytePosInASCIIRegion(firstIdx)] = isPrintable(firstByte) ? firstByte : '.';

        firstByte = lastByte;
        firstIdx = 0;
    }
    
    // y == E.metadata.numRows => append to lastByte and need to create a new row
    if (y >= E.metadata.numRows || lastByte != '\0') {
        char buf[2] = {lastByte};
        createRow(buf, 1);
    }
}

void deleteByte(const unsigned int x, const unsigned int y) {
    if (!isFirstHex(x))
        die("deleteByte: invalid x position");

    char firstIdx = posToByteIdx(x);
    for (unsigned int i = y; i < E.metadata.numRows; ++i) {
        char *row = E.metadata.text[i];

        rowForwardOne(row, firstIdx);
        firstIdx = 0;

        if (i < E.metadata.numRows - 1) {
            char c = getNthRowByte(E.metadata.text[i+1], 0);
            row[nthBytePosInHexRegion(BYTES_PER_ROW - 1)]     = intToHex(c/16);
            row[nthBytePosInHexRegion(BYTES_PER_ROW - 1) + 1] = intToHex(c%16);
            row[nthBytePosInASCIIRegion(BYTES_PER_ROW - 1)]   = isPrintable(c) ? c : '.';
        }
    }
    
    int lastRowBytes = getLastRowBytesNum();
    if (lastRowBytes == BYTES_PER_ROW) {
        char *lastRow = E.metadata.text[E.metadata.numRows - 1];
        int idx = BYTES_PER_ROW - 1;
        lastRow[nthBytePosInHexRegion(idx)]     = ' ';
        lastRow[nthBytePosInHexRegion(idx) + 1] = ' ';
        lastRow[nthBytePosInASCIIRegion(idx)]   = '\0';
    } else if (lastRowBytes == 0) {
        --E.metadata.numRows;
    }
}

void editorEditChar(int c) {
    if (getCurRegion() == HEX && (c < '0' || c > 'f' || (c > '9' && c < 'a')))
        return;
    
    editorRowEditChar(E.metadata.x, E.metadata.y, c);
    forwardCurOne();
}

void editorInsertChar() {
    unsigned int atX = E.metadata.x;
    unsigned int atY = E.metadata.y;

    // only support insert in hex region
    if (getRegion(atX) != HEX)
        return;
    
    setDirty();

    // 00000000: 1234 1234 1234 ...
    //  prepend 00 if at in odd position
    //  append  00 if at in even position
    bool prepend = isFirstHex(atX);

    if (!prepend) {
        if (isLastByte(atX, atY)) {
            if (getLastRowBytesNum() == BYTES_PER_ROW) {
                char buf[2] = {'\0'};
                createRow(buf, 1);
            } else {
                int idx = getByteIdxInHexRegion(atX) + 1;
                E.metadata.text[atY][nthBytePosInHexRegion(idx)]   = '0';
                E.metadata.text[atY][nthBytePosInHexRegion(idx)+1] = '0';
                E.metadata.text[atY][nthBytePosInASCIIRegion(idx)] = '.';
            }
            return;
        }

        forwardOneByte(&atX, &atY);
    }

    insertByte(atX, atY);

    if (prepend)
        forwardCurOneByte();
}


void editorDelChar(editorKey key) {
    if (key != DEL_KEY && key != BACKSPACE)
        die("editorDelChar: invalid key");

    
    //  00000000: 1234 1234 1234 ...
    //  BACKSPACE: remove previous byte if x in odd position
    //  DEL_KEY:   remove next byte if x in even position

    if (
        (key == BACKSPACE && !isFirstHex(E.metadata.x)) ||
        (key == DEL_KEY && isFirstHex(E.metadata.x)) 
    ) {
        return;
    }

    if (
        (key == BACKSPACE && !hasPrev(E.metadata.x, E.metadata.y)) ||
        (key == DEL_KEY && !hasNext(E.metadata.x, E.metadata.y))
    ) {
        return;
    }

    unsigned int atX = E.metadata.x;
    unsigned int atY = E.metadata.y;

    // align to first hex
    if (key == DEL_KEY)
        forwardOne(&atX, &atY);

    key == BACKSPACE ? backwardOneByte(&atX, &atY) : forwardOneByte(&atX, &atY);
    deleteByte(atX, atY);

    if (key == BACKSPACE)
        backwardCurOneByte();

    setDirty();
}

void openEditor(const char *filename) {
    free(E.conf.filename);
    E.conf.filename = strdup(filename);

    int fp = open(filename, O_RDONLY);
    if (fp < 0)
        die("Invalid file: maybe not exist or file is empty");

    char buf[BYTES_PER_ROW + 1] = "";
    int len;
    while (true) {
        len = read(fp, &buf, BYTES_PER_ROW);
        if (len <= 0)
            break;

        buf[len] = '\0';
        createRow(buf, len);
    }

    close(fp);
}

static void editorSave() {
    if (!E.metadata.isDirty)
        return;

    unsigned int len = 0;
    if (E.metadata.numRows > 0)
        len = BYTES_PER_ROW * (E.metadata.numRows - 1) + getLastRowBytesNum();

    char *buf = calloc(1, len + 1);
    if (buf == NULL)
        die("calloc");

    for (unsigned int i = 0; i < E.metadata.numRows; ++i)
        for (unsigned int j = 0; j < BYTES_PER_ROW; ++j) { 
            unsigned int idx = i*BYTES_PER_ROW + j;
            if (idx >= len)
                break;

            buf[idx] = getNthRowByte(E.metadata.text[i], j);
        }

    int fd = open(E.conf.filename, O_RDWR | O_CREAT, 0644);
    if (fd == -1)
        goto openFail;
    
    if (write(fd, buf, len) != len)
        goto writeFail;
    

    close(fd);
    free(buf);

    editorSetStatusMessage("%d bytes written to disk", len);
    setClean();
    return;

openFail:
    editorSetStatusMessage("Can't save! I/O error: %s", strerror(errno));

writeFail:
    close(fd);
    free(buf);
}

static void append(char **p, const char *s, unsigned int len) {
    if (len == POSTIVE_INFINITY)
        len = strlen(s);

    if (strlen(s) > len)
        die("append: invalid");

    char *buf = *p;
    int bufLen = buf ? strlen(buf) : 0;
    buf = realloc(buf, bufLen + len + 1);
    if (buf == NULL)
        die("realloc");

    memcpy(&buf[bufLen], s, len);
    buf[bufLen+len] = '\0';
    *p = buf;
}

static void editorScroll() {
    // up
    if (E.metadata.y < E.metadata.pageFirstRowIdx)
        E.metadata.pageFirstRowIdx = E.metadata.y;

    // down
    if (E.metadata.y >= E.metadata.pageFirstRowIdx + E.conf.screenRow)
        E.metadata.pageFirstRowIdx = E.metadata.y - E.conf.screenRow + 1;
    
    // left
    if (E.metadata.x < E.metadata.pageFirstColIdx)
        E.metadata.pageFirstColIdx = E.metadata.x;

    // right
    if (E.metadata.x >= E.metadata.pageFirstColIdx + E.conf.screenCol)
        E.metadata.pageFirstColIdx = E.metadata.x - E.conf.screenCol + 1;
}

static void editorDrawRows(char **buf) {
    for (unsigned int i = 0; i < E.conf.screenRow; ++i) {
        unsigned int r = E.metadata.pageFirstRowIdx  + i;
        if (r >= E.metadata.numRows) {
            append(buf, "~", POSTIVE_INFINITY);
        } else if (E.metadata.numRows == 0 && r == E.conf.screenRow / 3) {
            char welcome[80];
            unsigned int len = snprintf(welcome, sizeof(welcome), "editor -- version %s", VERSION);
            if (len > E.conf.screenCol)
                len = E.conf.screenCol;
                
        int padding = (E.conf.screenCol - len) / 2;
            if (padding) {
                append(buf, "~", POSTIVE_INFINITY);
                padding--;
            }

            while (padding--)
                append(buf, " ", POSTIVE_INFINITY);

            append(buf, welcome, POSTIVE_INFINITY);
        } else {
            unsigned int len = strlen(E.metadata.text[r]) - E.metadata.pageFirstColIdx;
            if (len > E.conf.screenCol)
                len = E.conf.screenCol;

            if (len > 0) {
                append(buf, &E.metadata.text[r][E.metadata.pageFirstColIdx], len);
            }
        }

        append(buf, "\x1b[K", POSTIVE_INFINITY);
        append(buf, "\r\n", POSTIVE_INFINITY);
    }
}

static void editorDrawMessageBar(char **buf) {
    append(buf, "\x1b[K", POSTIVE_INFINITY);
    unsigned int len = E.metadata.statusMsg? strlen(E.metadata.statusMsg) : 0;
    if (len > E.conf.screenCol)
        len = E.conf.screenCol;

    if (len && time(NULL) - E.metadata.statusTime < 5)
        append(buf, E.metadata.statusMsg, len);
}

static void editorRefreshScreen() {
    editorScroll();
    char *buf = NULL;
    append(&buf, "\x1b[2J", POSTIVE_INFINITY);
    append(&buf, "\x1b[H", POSTIVE_INFINITY);

    editorDrawRows(&buf);
    editorDrawMessageBar(&buf);
    
    char lineInfo[32];
    snprintf(lineInfo, sizeof(lineInfo), "\x1b[%d;%dH", E.metadata.y - E.metadata.pageFirstRowIdx + 1, E.metadata.x - E.metadata.pageFirstColIdx + 1);
    append(&buf, lineInfo, POSTIVE_INFINITY);
    append(&buf, "\x1b[?25h", POSTIVE_INFINITY);

    write(STDOUT_FILENO, buf, strlen(buf));
    free(buf);
}

static void editorSetStatusMessage(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (E.metadata.statusMsg) {
        free(E.metadata.statusMsg);
        E.metadata.statusMsg = NULL;
    }

    char *msg = calloc(1, ROW_LEN);
    if (msg == NULL)
        die("calloc");

    vsnprintf(msg, ROW_LEN, fmt, args);
    va_end(args);

    E.metadata.statusMsg = msg;
    E.metadata.statusTime = time(NULL);
}

static void editorMoveCursor(int key) {
    switch (key) {
        case ARROW_LEFT:
            backwardCurOne();
            break;

        case ARROW_RIGHT:
            forwardCurOne();
            break;

        case ARROW_UP:
            if (E.metadata.y != 0) {
                E.metadata.y--;
            }
            break;

        case ARROW_DOWN:
            if (E.metadata.y != E.metadata.numRows - 1) {
                ++E.metadata.y;
                while (E.metadata.x <= HEX_END_POS && E.metadata.x > HEX_START_POS && E.metadata.text[E.metadata.y][E.metadata.x] == ' ')
                    E.metadata.x--;
                while (E.metadata.x <= ASCII_END_POS && E.metadata.x > ASCII_START_POS && E.metadata.text[E.metadata.y][E.metadata.x] == '\0')
                    E.metadata.x--;
            }
            break;
    }

}

static void editorProcessKeypress() {
    static int quit_times = QUIT_TIMES;
    int c = editorReadKey();

    if (c != CTRL_KEY('q'))
        editorSetStatusMessage("HELP: Ctrl-S = save | Ctrl-Q = quit | Ctrl-F = find | Ctrl-I = Insert NULL");

    switch (c) {
        case '\r':
            break;

        case CTRL_KEY('i'):
            editorInsertChar();
            break;

        case CTRL_KEY('q'):
            if (E.metadata.isDirty && quit_times > 0) {
                editorSetStatusMessage("WARNING!!! File has unsaved changes. Press Ctrl-Q %d more times to quit.", quit_times);
                --quit_times;
                return;
            }

            write(STDOUT_FILENO, "\x1b[2J", 4);
            write(STDOUT_FILENO, "\x1b[H", 3);
            terminate(0);
            break;

        case CTRL_KEY('s'):
            editorSave();
            break;

        case HOME_KEY:
            E.metadata.x = HEX_START_POS+1;
            break;

        case END_KEY:
            if (E.metadata.y < E.metadata.numRows)
                E.metadata.x = strlen(E.metadata.text[E.metadata.y]) - 1;
            break;

        case CTRL_KEY('f'):
            // TODO
            break;

        case BACKSPACE:
        case DEL_KEY:
            editorDelChar(c);
            break;

        case PAGE_UP:
        case PAGE_DOWN:
          {
            int times = E.conf.screenRow;
            while (times--)
                editorMoveCursor( c == PAGE_UP ? ARROW_UP : ARROW_DOWN);
            break;
          }
        case ARROW_UP:
        case ARROW_DOWN:
        case ARROW_LEFT:
        case ARROW_RIGHT:
            editorMoveCursor(c);
            break;

        case CTRL_KEY('l'):
        case '\x1b':
            break;

        default:
            editorEditChar(c);
            break;
    }

    quit_times = QUIT_TIMES;
}

static void initEditor() {
    E.metadata.x = ADDR_LEN+2;
    E.metadata.y = 0;
    E.metadata.numRows = 0;
    E.metadata.pageFirstRowIdx = 0;
    E.metadata.pageFirstColIdx = 0;

    E.metadata.text = NULL;
    E.metadata.statusMsg = NULL;
    E.metadata.statusTime = 0;
    E.metadata.isDirty = false;

    E.conf.filename = NULL;
    if (getWindowSize(&E.conf.screenRow, &E.conf.screenCol) == -1)
        die("initEditor: getWindowSize");
    
    if (E.conf.screenRow == 0 || E.conf.screenCol < 1)
        die("initEditor: invalid screen size");

    // space for status/help
    E.conf.screenRow -= 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage ./hxd <file>\n");
        terminate(1);
    }

    enableRawMode();
    initEditor();
    openEditor(argv[1]);
    editorSetStatusMessage("HELP: Ctrl-S = save | Ctrl-Q = quit | Ctrl-F = find | Ctrl-I = Insert NULL");

    while (1) {
        editorRefreshScreen();
        editorProcessKeypress();
    }

    return 0;
}