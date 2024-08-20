FROM debian:12.6

WORKDIR /var/android_sdk

COPY data/cmdline-tools /var/android_sdk/cmdline-tools
COPY data/exec.sh /var/android_sdk/exec.sh
COPY /data/bin /usr/local/bin
VOLUME /data

ENV ANDROID_HOME=/var/android_sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
ENV PATH=$PATH:$ANDROID_HOME/emulator
ENV PATH=$PATH:$ANDROID_HOME/platform-tools

RUN apt-get update -y && \
    apt-get install default-jdk libpulse0 -y && \
    sdkmanager --sdk_root=$ANDROID_HOME && \
    yes | sdkmanager 'system-images;android-30;google_apis;x86' 'emulator' 'platform-tools' 'platforms;android-30' && \
    echo "no" | avdmanager create avd -k 'system-images;android-30;google_apis;x86' -n Nexus_XL_API_30

CMD ["./exec.sh"]


# Libpcap é uma dependência necessária para o tcpdump
#wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz
#wget https://www.tcpdump.org/release/tcpdump-4.99.4.tar.gz

# Extraia os arquivos
#tar -xzf libpcap-1.10.4.tar.gz
#tar -xzf tcpdump-4.99.4.tar.gz

#cd libpcap-1.10.4
# 2025  make clean
# 2026  CFLAGS="-m32" LDFLAGS="-m32" ./configure --prefix=/home/jose/Documentos/projeto-integrador/Kyrios/KyriosManager/KyriosMachine/KyriosEngine/data
# 2027  make
# 2028  sudo make install
#cd ..

#cd tcpdump-4.99.4
# 2025  make clean
# 2026  CFLAGS="-m32" LDFLAGS="-m32" ./configure --prefix=/home/jose/Documentos/projeto-integrador/Kyrios/KyriosManager/KyriosMachine/KyriosEngine/data
# 2027  make
# 2028  sudo make install
#cd ..


########
#adb push /usr/local/bin/tcpdump /data/local/tmp/tcpdump
#adb shell chmod +x /data/local/tmp/tcpdump
#adb shell /data/local/tmp/tcpdump -i any -p -s 0 -w /data/local/tmp/capture.pcap



