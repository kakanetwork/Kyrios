FROM debian:12.6

WORKDIR /var/android_sdk

COPY data/cmdline-tools /var/android_sdk/cmdline-tools
COPY data/exec.sh /var/android_sdk/exec.sh

ENV ANDROID_HOME=/var/android_sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
ENV PATH=$PATH:$ANDROID_HOME/emulator
ENV PATH=$PATH:$ANDROID_HOME/platform-tools

RUN apt-get update -y && \
    apt-get install default-jdk libpulse0 -y tcpdump && \
    sdkmanager --sdk_root=$ANDROID_HOME && \
    yes | sdkmanager 'system-images;android-30;google_apis;x86' 'emulator' 'platform-tools' 'platforms;android-30' && \
    echo "no" | avdmanager create avd -k 'system-images;android-30;google_apis;x86' -n Nexus_XL_API_30

CMD ["./exec.sh"]




