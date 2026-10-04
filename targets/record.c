#include <stdio.h>
#include <string.h>
#include <stdint.h>
static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
int main(void) {
    char line[1024], payload[600], extra;
    unsigned char raw[255], out[520];
    long long kind, seq, flags;
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "%lld %lld %lld %599s %c", &kind, &seq, &flags, payload, &extra) != 4 ||
            kind < 0 || kind > 15 || seq < 0 || seq > 65535 || flags < 0 || flags > 3) { puts("ERR"); continue; }
        int n = !strcmp(payload, "-") ? 0 : (int)strlen(payload);
        int bad = n % 2 || n > 510;
        for (int i = 0; !bad && i < n; i += 2) {
            int a = nibble(payload[i]), b = nibble(payload[i+1]);
            if (a < 0 || b < 0) bad = 1;
            else raw[i/2] = (unsigned char)((a << 4) | b);
        }
        if (bad) { puts("ERR"); continue; }
        n /= 2;
        int p = 0;
        out[p++] = 0xb6; out[p++] = (unsigned char)(0x40 | kind);
        out[p++] = (unsigned char)flags;
        out[p++] = (unsigned char)seq; out[p++] = (unsigned char)(seq >> 8);
        out[p++] = (unsigned char)n;
        for (int i = 0; i < n; ++i) {
            unsigned char x = raw[(flags & 1) ? n - 1 - i : i];
            if (flags & 2) x ^= (unsigned char)(seq + 17 * i + kind);
            out[p++] = x;
        }
        uint16_t check = 0x1d0f;
        for (int i = 0; i < p; ++i) check = (uint16_t)((check << 5) | (check >> 11)) ^ out[i];
        out[p++] = (unsigned char)(check >> 8); out[p++] = (unsigned char)check;
        for (int i = 0; i < p; ++i) printf("%02x", out[i]);
        putchar('\n');
    }
    return 0;
}
