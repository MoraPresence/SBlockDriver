 #!/bin/bash

insmod cryptoDriver.ko

major_number=`dmesg | tail -1 | awk '{print $9}'`
mknod /dev/cryptoDriver c $major_number 0


echo "Put the parameters: "
echo "examples:"
echo "encrypt /path/what/to/encrypt /path/where/output /key/path block_size"
echo "or"
echo "decrypt /path/what/to/decrypt /path/where/output /key/path block_size"
echo "where block_size = 8 16 32 64 128 256"

read text

echo "$text" > /dev/cryptoDriver

rmmod cryptoDriver
rm /dev/cryptoDriver
