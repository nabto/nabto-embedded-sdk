#include <nabto/nabto_device.h>

#include <modules/iam/nm_iam.h>

#include <stdio.h>

int main(int argc, char** argv) {
    printf("Nabto device version %s\n", nabto_device_version());

}
