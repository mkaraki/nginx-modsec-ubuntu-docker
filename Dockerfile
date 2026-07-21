FROM ubuntu:resolute@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb

# IMPORTANT NOTE: this renovate check will fail due to renovate didn't support ubuntu package versioning.
# Version info: https://packages.ubuntu.com/resolute/nginx-full
# renovate-ubuntu: suite=noble depName=nginx-full
ARG NGINX_FULL_VERSION="1.28.3-2ubuntu1.8"

# Version info: https://packages.ubuntu.com/resolute/libnginx-mod-http-modsecurity
# renovate-ubuntu: suite=noble depName=libnginx-mod-http-modsecurity 
ARG LIBNGINX_MOD_SECURITY_VERSION="1.0.3-2build6"

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    nginx-full="${NGINX_FULL_VERSION}" \
    libnginx-mod-http-modsecurity="${LIBNGINX_MOD_SECURITY_VERSION}" \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/nginx/modsecurity.conf &&\
    sed -i 's/^#include /include /' /etc/nginx/modsecurity_includes.conf &&\
    echo "modsecurity on;" > /etc/nginx/conf.d/modsecurity.conf &&\
    echo "modsecurity_rules_file /etc/nginx/modsecurity_includes.conf;" >> /etc/nginx/conf.d/modsecurity.conf &&\
    sed -i 's/^IncludeOptional /Include /' /usr/share/modsecurity-crs/owasp-crs.load &&\
    sed -i 's/# server_tokens off;$/server_tokens off;/' /etc/nginx/nginx.conf &&\
    sed -i 's:access_log /var/log/nginx/access.log;$:access_log /dev/stdout;:' /etc/nginx/nginx.conf &&\
    echo "error_log /dev/stderr;" > /etc/nginx/conf.d/error_log_stderr.conf &&\
    unlink /etc/nginx/sites-enabled/default

#RUN echo "SecPcreMatchLimit 200000" >> /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf &&\
#    echo "SecPcreMatchLimitRecursion 200000" >> /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

EXPOSE 80/tcp
EXPOSE 443/tcp
EXPOSE 443/udp

STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]
