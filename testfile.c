#include <string.h>
#include <stdio.h>

void vulnerable_function() {
    char buffer[10];
    strcpy(buffer, "thisiswaytoolong");
    printf("Buffer: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}
