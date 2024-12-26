FROM gcr.io/forgerock-io/idm-cdk:7.4.1

COPY debian-buster-sources.list /etc/apt/sources.list

# Harden IDM by removing the Felix OSGI Console. Unless you are a ForgeRock developer, the
# console is rarely required. Your configuration should NOT include conf/felix.webconsole.json
RUN rm -f bundle/org.apache.felix.webconsole*.jar  && \
    rm -f bundle/openidm-felix-webconsole-*.jar

# Remove this once https://bugster.forgerock.org/jira/browse/OPENIDM-16100 is integrated
# This sets the RAM based on cgroups to 65% of the container memory
ENV JAVA_OPTS -XX:MaxRAMPercentage=65 -XX:InitialRAMPercentage=65 -XX:MaxTenuringThreshold=1 -Djava.security.egd=file:/dev/urandom -XshowSettings:vm  -XX:+PrintFlagsFinal

ARG CONFIG_PROFILE=cdk
RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /opt/openidm
COPY --chown=forgerock:root bin/import-pem-certs.sh /opt/openidm/bin
COPY --chown=forgerock:root . /opt/openidm
COPY --chown=forgerock:root script/* /opt/openidm/script

# Copy new empty security files into the container
COPY --chown=forgerock:root security/storepass /opt/openidm/security/new_storepass
COPY --chown=forgerock:root security/truststore /opt/openidm/security/new_truststore
COPY --chown=forgerock:root security/keystore.jceks /opt/openidm/security/new_keystore.jceks

# Copy contents of existing files into new files, backup originals, remove originals, and rename new files
RUN \
    # Step 1: Backup existing files
    cp /opt/openidm/security/storepass /opt/openidm/security/storepass_bk && \
    cp /opt/openidm/security/truststore /opt/openidm/security/truststore_bk && \
    cp /opt/openidm/security/keystore.jceks /opt/openidm/security/keystore.jceks_bk && \
    \
    # Step 2: Copy contents of existing files into new files
    cat /opt/openidm/security/storepass >> /opt/openidm/security/new_storepass && \
    cat /opt/openidm/security/truststore >> /opt/openidm/security/new_truststore && \
    cat /opt/openidm/security/keystore.jceks >> /opt/openidm/security/new_keystore.jceks && \
    \
    # Step 3: Remove existing files
    rm /opt/openidm/security/storepass && \
    rm /opt/openidm/security/truststore && \
    rm /opt/openidm/security/keystore.jceks && \
    rm /opt/openidm/security/storepass_bk && \
    rm /opt/openidm/security/truststore_bk && \
    rm /opt/openidm/security/keystore.jceks_bk && \
    \
    # Step 4: Rename new files to original names
    mv /opt/openidm/security/new_storepass /opt/openidm/security/storepass && \
    mv /opt/openidm/security/new_truststore /opt/openidm/security/truststore && \
    mv /opt/openidm/security/new_keystore.jceks /opt/openidm/security/keystore.jceks

