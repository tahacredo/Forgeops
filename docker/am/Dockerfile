FROM gcr.io/forgerock-io/am-cdk:7.4.0

ARG CONFIG_PROFILE=cdk
RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY  --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /home/forgerock/openam/
COPY --chown=forgerock:root custom-nodes/* /usr/local/tomcat/webapps/am/WEB-INF/lib

COPY  --chown=forgerock:root security/keys/preprod /home/forgerock/openam/security/keys/preprod
COPY  --chown=forgerock:root security/keys/prod /home/forgerock/openam/security/keys/prod

COPY  --chown=forgerock:root security/keystores/preprod /home/forgerock/openam/security/keystores/preprod
COPY  --chown=forgerock:root security/keystores/prod /home/forgerock/openam/security/keystores/prod
COPY  --chown=forgerock:root security/keystores/keystore.jks /home/forgerock/openam/security/keystores/
COPY  --chown=forgerock:root security/keystores/keystore.jceks /home/forgerock/openam/security/keystores/keystore-new.jceks

COPY  --chown=forgerock:root security/secrets/encrypted/scripted.node.infobip.api.key /home/forgerock/openam/security/secrets/encrypted/
COPY  --chown=forgerock:root security/secrets/encrypted/preprod /home/forgerock/openam/security/secrets/encrypted/preprod
COPY  --chown=forgerock:root security/secrets/encrypted/prod /home/forgerock/openam/security/secrets/encrypted/prod

COPY --chown=forgerock:root *.sh /home/forgerock/

RUN mkdir -p /home/forgerock/logging

RUN \
    # Step 1: Backup existing files
    cat /home/forgerock/openam/security/keystores/keystore-new.jceks >> /home/forgerock/openam/security/keystores/keystore.jceks && \
    rm /home/forgerock/openam/security/keystores/keystore-new.jceks 

ENV CATALINA_OPTS="${CATALINA_OPTS} -Dlogback.configurationFile=/home/forgerock/logging/logback.xml"

WORKDIR /home/forgerock

# If you want to debug AM uncomment these lines:
#ENV JPDA_TRANSPORT=dt_socket
#ENV JPDA_ADDRESS *:9009
