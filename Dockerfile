FROM wazuh/wazuh-dashboard:4.9.0

USER root

RUN printf '%s\n' \
    'server.host: 0.0.0.0' \
    'server.port: 5601' \
    'server.ssl.enabled: false' \
    'opensearch.hosts: ["http://wazuh.indexer:9200"]' \
    'opensearch.ssl.verificationMode: none' \
    'opensearch.username: admin' \
    'opensearch.password: SecretPassword' \
    'opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]' \
    'opensearch_security.multitenancy.enabled: false' \
    'opensearch_security.readonly_mode.roles: ["kibana_read_only"]' \
    'server.defaultRoute: /app/wazuh' \
    'uiSettings.overrides.defaultRoute: /app/wazuh' \
    > /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

USER wazuh-dashboard
