AT97SC3204T I2C TPM U-boot support
=============================================

*Note:* This only includes a board config for the BeagleBone Black: am335x_boneblack_tpm

Also see the standalone reference: https://github.com/theopolis/sboot

## Instructions:

1. Install an ARMv7 cross compiler.
2. `make ARCH=arm CROSS_COMPILE=/cross/compiler am335x_boneblack_tpm_config`
3. `make ARCH=arm CROSS_COMPILE=/cross/compiler`
4. Move the compiled MLO and u-boot.img to your BeagleBone Black.

You may need to change settings in /include/configs/am335x_evm.h to 
match your boot, kernel, or partition configuration.

## Add TPM Support:

Use the following defines to add AT97SC3204T support to additional boards.

In your board configuration, add:
```
 #define CONFIG_TPM
 #define CONFIG_TPM_I2C_ATMEL
 #define CONFIG_TPM_I2C_BUS <number>
 #define CONFIG_TPM_I2C_ADDR 0x29
 #define CONFIG_CMD_TPM
```
