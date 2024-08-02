## ETAPA PARA TESTE (aprimorar)
    1. sudo docker build .
    2. sudo docker run -it [id_image] sh
    3. ./sdkmanager 'system-images;android-30;google_apis;x86'
    4. ./avdmanager create avd -c 100M -k 'system-images;android-30;google_apis;x86' -n Nexus_XL_API_30
    5. ./emulator -avd Nexus_XL_API_30







