FROM debian:12.6

WORKDIR /var/sdk_android

COPY cmdline-tools /var/sdk_android/cmdline-tools

RUN mkdir cmdline-tools/latest && \
    cd cmdline-tools && \
    mv bin latest && \
    mv lib latest && \
    mv NOTICE.txt latest && \
    mv source.properties latest

CMD ["tail", "-f", "/dev/null"]
