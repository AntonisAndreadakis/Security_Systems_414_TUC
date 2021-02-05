#!/bin/bash

echo "Give your AM"
read am

./assign_1 -i encryptme_256.txt -o decryptme_256.txt -p TUC$am -b 256 -e
./assign_1 -i hpy414_decryptme_128.txt -o hpy414_encryptme_128.txt -p hpy414 -b 128 -d
./assign_1 -i signme_128.txt -o verifyme_128.txt -p TUC$am -b 128 -s
./assign_1 -i hpy414_verifyme_256.txt -o hpy414_signme_256.txt -p hpy414 -b 256 -v
./assign_1 -i hpy414_verifyme_128.txt -o hpy414_signme_128.txt -p hpy414 -b 128 -v


