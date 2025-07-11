FROM ubuntu:noble

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    nginx-full \
    libnginx-mod-http-modsecurity \
    git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/nginx/modsecurity.conf &&\
    sed -i 's/^#include /include /' /etc/nginx/modsecurity_includes.conf &&\
    echo "modsecurity on;" >> /etc/nginx/conf.d/modsecurity.conf &&\
    echo "modsecurity_rules_file /etc/nginx/modsecurity_includes.conf;" >> /etc/nginx/conf.d/modsecurity.conf &&\
    sed -i 's/# server_tokens off;$/server_tokens off;/' /etc/nginx/nginx.conf &&\
    unlink /etc/nginx/sites-enabled/default

#RUN echo "SecPcreMatchLimit 200000" >> /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf &&\
#    echo "SecPcreMatchLimitRecursion 200000" >> /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

EXPOSE 80/tcp
EXPOSE 443/tcp
EXPOSE 443/udp

STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]
