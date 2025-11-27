FROM wazuh/wazuh-dashboard:4.9.0

USER root

RUN echo 'server.host: 0.0.0.0\n\
server.port: 5601\n\
server.ssl.enabled: false\n\
opensearch.hosts: ["http://wazuh.indexer:9200"]\n\
opensearch.ssl.verificationMode: none\n\
opensearch.username: admin\n\
opensearch.password: SecretPassword\n\
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]\n\
opensearch_security.multitenancy.enabled: false\n\
opensearch_security.readonly_mode.roles: ["kibana_read_only"]\n\
server.defaultRoute: /app/wazuh\n\
uiSettings.overrides.defaultRoute: /app/wazuh' > /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

USER wazuh-dashboard
