#include <stdio.h>
#include <string.h>
/* All arithmetic is bounded by the public input domain. */
int main(void) {
    char line[256], extra;
    long long unit, qty, member, coupon, region;
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "%lld %lld %lld %lld %lld %c", &unit, &qty, &member, &coupon, &region, &extra) != 5 ||
            unit < 0 || unit > 100000 || qty < 0 || qty > 200 || member < 0 || member > 2 ||
            coupon < 0 || coupon > 2 || region < 0 || region > 2) { puts("ERR"); continue; }
        if (!qty) { puts("0 0 0 0"); continue; }
        long long base = unit * qty;
        long long rate = qty >= 20 ? 12 : qty >= 7 ? 5 : 0;
        long long net = base - base * rate / 100;
        if (member == 1) net -= net * 3 / 100;
        if (member == 2) net -= net * 8 / 100;
        if (coupon == 1 && net >= 2500) net -= 375;
        if (coupon == 2 && qty >= 3 && member != 2) net -= net * 7 / 100;
        long long shipping = net >= 5000 ? 0 : 199 + 100 * region;
        long long taxrate = region == 0 ? 0 : region == 1 ? 650 : 825;
        long long tax = (net * taxrate + 9999) / 10000;
        printf("%lld %lld %lld %lld\n", net, shipping, tax, net + shipping + tax);
    }
    return 0;
}
