#include <stdio.h>

#include <nabto/nabto_device.h>

int main(int argc, char* argv[]) {
    printf("Nabto Embedded SDK verstion %s\r\n", nabto_device_version());
}
