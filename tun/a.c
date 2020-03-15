#include <stdio.h>

int main(int argc, char const *argv[]) {
    unsigned int x;
    printf("请输入营业额: ");
    scanf("%d", &x);
    switch (x / 100) {
    case 0:
    case 1:
        printf("提成为: %.2f\n", 100.00);
        break;
    case 2:
    case 3:
        printf("提成为: %.2f\n", 100 + x * 0.1);
        break;
    case 4:
        printf("提成为: %.2f\n", 100 + x * 0.3);
        break;
    default:
        printf("提成为: %.2f\n", 100 + x * 0.5);
        break;
    }

    return 0;
}
