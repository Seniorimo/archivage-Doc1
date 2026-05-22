package com.example.archivage_Doc.Utils;

// INTENTIONAL VULN - GITLEAKS: Hardcoded secrets for PFE demo
// This class is not used in business logic, only for secret detection testing
public class HardcodedSecretsDemo {

    // AWS Credentials
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String AWS_SESSION_TOKEN = "FwoGZXIvYXdzEG0aDGp6rJk0EXAMPLE";

    // GitHub Personal Access Token
    private static final String GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String GITHUB_OAUTH_TOKEN = "gho_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Google Cloud Service Account Key (partial)
    private static final String GCP_SERVICE_ACCOUNT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2MjM0NTY3ODkwIiwidHlwIjoiSldUIn0";

    // Stripe API Keys
    private static final String STRIPE_PUBLISHABLE_KEY = "pk_live_51MzABC123xyz456789";
    private static final String STRIPE_SECRET_KEY = "sk_live_51MzABC123xyz456789abcDEFghij456789";

    // Slack Bot Token
    private static final String SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String SLACK_USER_TOKEN = "xoxp-1234567890-1234567890-1234567890-abcdefghijklmnopqrstuvwxyz";

    // SendGrid API Key
    private static final String SENDGRID_API_KEY = "SG.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Twilio API Credentials
    private static final String TWILIO_ACCOUNT_SID = "AC1234567890abcdefghijklmnopqrstuvwxyz";
    private static final String TWILIO_AUTH_TOKEN = "1234567890abcdefghijklmnopqrstuvwxyz1234567890ab";

    // Firebase Private Key (partial)
    private static final String FIREBASE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC";

    // Datadog API Key
    private static final String DATADOG_API_KEY = "1234567890abcdefghijklmnopqrstuvwxyz1234567890ab";

    // PagerDuty API Key
    private static final String PAGERDUTY_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // CircleCI Personal Token
    private static final String CIRCLECI_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Heroku API Key
    private static final String HEROKU_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // npm Token
    private static final String NPM_TOKEN = "npm_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // PyPI API Token
    private static final String PYPI_TOKEN = "pypi-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Docker Hub Token
    private static final String DOCKER_HUB_TOKEN = "dckr_pat_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // GitLab Personal Access Token
    private static final String GITLAB_TOKEN = "glpat-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Bitbucket App Password
    private static final String BITBUCKET_PASSWORD = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Azure Storage Key
    private static final String AZURE_STORAGE_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab";

    // JWT Secret Keys
    private static final String JWT_SECRET_KEY = "super-secret-jwt-key-for-demo-purposes-1234567890";
    private static final String JWT_HS256_KEY = "HS256-secret-key-for-testing-1234567890abcdef";

    // Database Passwords
    private static final String MYSQL_ROOT_PASSWORD = "RootPassword123!";
    private static final String POSTGRES_PASSWORD = "PostgresPassword456!";
    private static final String MONGODB_PASSWORD = "MongoPassword789!";

    // API Keys
    private static final String GOOGLE_MAPS_API_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private static final String OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String HUGGINGFACE_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // OAuth Client Secrets
    private static final String GOOGLE_CLIENT_SECRET = "GOCSPX-abcdefghijklmnopqrstuvwxyz1234567890";
    private static final String FACEBOOK_APP_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Private SSH Key (partial)
    private static final String SSH_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA";

    // PGP Private Key (partial)
    private static final String PGP_PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: BCPG v1.68";

    // Salesforce Password
    private static final String SALESFORCE_PASSWORD = "SalesforcePassword123!SecurityToken";

    // Jira API Token
    private static final String JIRA_API_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Confluence API Token
    private static final String CONFLUENCE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Jenkins API Token
    private static final String JENKINS_API_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // SonarQube Token
    private static final String SONARQUBE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Grafana API Key
    private static final String GRAFANA_API_KEY = "eyJrIjoiabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // New Relic License Key
    private static final String NEW_RELIC_LICENSE_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Splunk Token
    private static final String SPLUNK_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Segment Write Key
    private static final String SEGMENT_WRITE_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Intercom API Key
    private static final String INTERCOM_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Mailgun API Key
    private static final String MAILGUN_API_KEY = "key-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Mailchimp API Key
    private static final String MAILCHIMP_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890-us12";

    // Auth0 Client Secret
    private static final String AUTH0_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Okta API Token
    private static final String OKTA_API_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Shopify API Key
    private static final String SHOPIFY_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String SHOPIFY_PASSWORD = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Square Access Token
    private static final String SQUARE_ACCESS_TOKEN = "EAAAEabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Braintree Merchant ID
    private static final String BRAINTREE_MERCHANT_ID = "abcdefghijklmnopqrstuvwxyz1234567890";

    // PayPal Client ID
    private static final String PAYPAL_CLIENT_ID = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String PAYPAL_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Stripe Webhook Secret
    private static final String STRIPE_WEBHOOK_SECRET = "whsec_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // AWS RDS Master Password
    private static final String AWS_RDS_PASSWORD = "AdminPassword123!SecureDB";

    // Redis Password
    private static final String REDIS_PASSWORD = "RedisPassword456!Cache";

    // Elasticsearch Password
    private static final String ELASTICSEARCH_PASSWORD = "ElasticPassword789!Search";

    // RabbitMQ Password
    private static final String RABBITMQ_PASSWORD = "RabbitMQPassword123!Queue";

    // Kafka SASL Password
    private static final String KAFKA_PASSWORD = "KafkaPassword456!Stream";

    // Consul Token
    private static final String CONSUL_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Vault Token
    private static final String VAULT_TOKEN = "s.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Nomad Token
    private static final String NOMAD_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Terraform Cloud Token
    private static final String TERRAFORM_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Ansible Vault Password
    private static final String ANSIBLE_VAULT_PASSWORD = "AnsibleVaultPassword123!";

    // Kubernetes Service Account Token (partial)
    private static final String K8S_SA_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE";

    // AWS Lambda Environment Variable
    private static final String LAMBDA_ENV_KEY = "lambda_secret_key_1234567890";

    // Slack Webhook URL
    private static final String SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX";

    // Discord Bot Token
    private static final String DISCORD_BOT_TOKEN = "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GhIjKl.MnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWx";

    // Telegram Bot Token
    private static final String TELEGRAM_BOT_TOKEN = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    // Twitter API Keys
    private static final String TWITTER_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String TWITTER_API_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String TWITTER_ACCESS_TOKEN = "1234567890-abcdefghijklmnopqrstuvwxyz1234567890";
    private static final String TWITTER_ACCESS_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // LinkedIn Client Secret
    private static final String LINKEDIN_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Dropbox API Secret
    private static final String DROPBOX_API_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Box API Key
    private static final String BOX_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890";

    // OneDrive Client Secret
    private static final String ONEDRIVE_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Google Cloud SQL Password
    private static final String GCP_SQL_PASSWORD = "GoogleSQLPassword123!";

    // AWS S3 Secret Key
    private static final String AWS_S3_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY2";

    // AWS IAM Access Key
    private static final String AWS_IAM_KEY = "AKIAIOSFODNN7EXAMPLE2";

    // AWS KMS Key ID
    private static final String AWS_KMS_KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";

    // Azure Service Principal Secret
    private static final String AZURE_SP_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // DigitalOcean API Token
    private static final String DIGITALOCEAN_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Linode API Key
    private static final String LINODE_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Vultr API Key
    private static final String VULTR_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // OVH API Key
    private static final String OVH_APPLICATION_KEY = "abcdefghijklmnopqrstuvwxyz1234567890";
    private static final String OVH_APPLICATION_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890";
    private static final String OVH_CONSUMER_KEY = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Scaleway API Key
    private static final String SCALEWAY_API_KEY = "SCWabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Exoscale API Key
    private static final String EXOSCALE_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Hetzner API Token
    private static final String HETZNER_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Cloudflare API Key
    private static final String CLOUDFLARE_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Fastly API Token
    private static final String FASTLY_API_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Akamai Edge Grid Token
    private static final String AKAMAI_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Imperva API Key
    private static final String IMPERVA_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // F5 BIG-IP Password
    private static final String F5_PASSWORD = "F5Password123!LoadBalancer";

    // Cisco Meraki API Key
    private static final String MERAKI_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Palo Alto API Key
    private static final String PALO_ALTO_KEY = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Fortinet API Token
    private static final String FORTINET_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Check Point API Key
    private static final String CHECKPOINT_KEY = "abcdefghijklmnopqrstuvwxyz1234567890";

    // Juniper API Token
    private static final String JUNIPER_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // VMware vCenter Password
    private static final String VCENTER_PASSWORD = "VMwarePassword123!Virtualization";

    // Nutanix API Key
    private static final String NUTANIX_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Citrix ADC Password
    private static final String CITRIX_PASSWORD = "CitrixPassword123!ADC";

    // SAP Password
    private static final String SAP_PASSWORD = "SAPPassword123!Enterprise";

    // Oracle Database Password
    private static final String ORACLE_PASSWORD = "OraclePassword123!Database";

    // SQL Server Password
    private static final String SQLSERVER_PASSWORD = "SQLServerPassword123!Microsoft";

    // Cassandra Password
    private static final String CASSANDRA_PASSWORD = "CassandraPassword456!NoSQL";

    // Couchbase Password
    private static final String COUCHBASE_PASSWORD = "CouchbasePassword789!Document";

    // Neo4j Password
    private static final String NEO4J_PASSWORD = "Neo4jPassword123!Graph";

    // InfluxDB Password
    private static final String INFLUXDB_PASSWORD = "InfluxDBPassword456!TimeSeries";

    // TimescaleDB Password
    private static final String TIMESCALEDB_PASSWORD = "TimescaleDBPassword789!PostgreSQL";

    // ClickHouse Password
    private static final String CLICKHOUSE_PASSWORD = "ClickHousePassword123!Analytics";

    // Presto Password
    private static final String PRESTO_PASSWORD = "PrestoPassword456!SQL";

    // Trino Password
    private static final String TRINO_PASSWORD = "TrinoPassword789!DistributedQuery";

    // Apache Druid Password
    private static final String DRUID_PASSWORD = "DruidPassword123!OLAP";

    // Apache Pinot Password
    private static final String PINOT_PASSWORD = "PinotPassword456!RealTime";

    // Apache Solr Password
    private static final String SOLR_PASSWORD = "SolrPassword789!Search";

    // Elasticsearch API Key
    private static final String ELASTICSEARCH_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // OpenSearch Password
    private static final String OPENSEARCH_PASSWORD = "OpenSearchPassword123!AWS";

    // Grafana Cloud API Key
    private static final String GRAFANA_CLOUD_KEY = "eyJrIjoiabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Loki Token
    private static final String LOKI_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE";

    // Prometheus Bearer Token
    private static final String PROMETHEUS_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE";

    // Alertmanager Webhook URL
    private static final String ALERTMANAGER_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX";

    // Thanos S3 Access Key
    private static final String THANOS_S3_KEY = "AKIAIOSFODNN7EXAMPLE3";

    // Cortex Token
    private static final String CORTEX_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Mimir Token
    private static final String MIMIR_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Tempo Token
    private static final String TEMPO_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Pyroscope Token
    private static final String PYROSCOPE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Parca Token
    private static final String PARCA_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Jaeger Token
    private static final String JAEGER_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Zipkin API Key
    private static final String ZIPKIN_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Honeycomb API Key
    private static final String HONEYCOMB_API_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Lightstep Access Token
    private static final String LIGHTSTEP_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Datadog App Key
    private static final String DATADOG_APP_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // AppDynamics API Key
    private static final String APPDYNAMICS_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Dynatrace API Token
    private static final String DYNATRACE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Splunk HEC Token
    private static final String SPLUNK_HEC_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Logstash Output Password
    private static final String LOGSTASH_PASSWORD = "LogstashPassword123!Pipeline";

    // Filebeat Output Password
    private static final String FILEBEAT_PASSWORD = "FilebeatPassword456!Shipper";

    // Metricbeat Output Password
    private static final String METRICBEAT_PASSWORD = "MetricbeatPassword789!Metrics";

    // Heartbeat Output Password
    private static final String HEARTBEAT_PASSWORD = "HeartbeatPassword123!Uptime";

    // Packetbeat Output Password
    private static final String PACKETBEAT_PASSWORD = "PacketbeatPassword456!Network";

    // Auditbeat Output Password
    private static final String AUDITBEAT_PASSWORD = "AuditbeatPassword789!Audit";

    // Journalbeat Output Password
    private static final String JOURNALBEAT_PASSWORD = "JournalbeatPassword123!Systemd";

    // Functionbeat Output Password
    private static final String FUNCTIONBEAT_PASSWORD = "FunctionbeatPassword456!Serverless";

    // APM Server Secret Token
    private static final String APM_SECRET_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Enterprise Search Password
    private static final String ENTERPRISE_SEARCH_PASSWORD = "EnterpriseSearchPassword789!Elastic";

    // App Search API Key
    private static final String APP_SEARCH_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Workplace Search API Key
    private static final String WORKPLACE_SEARCH_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // ECE Admin Password
    private static final String ECE_PASSWORD = "ECEPassword123!ElasticCloud";

    // ECK Admin Password
    private static final String ECK_PASSWORD = "ECKPassword456!Kubernetes";

    // Kibana Encryption Key
    private static final String KIBANA_ENCRYPTION_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Logz.io API Token
    private static final String LOGZIO_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Sumo Logic Access Key
    private static final String SUMOLOGIC_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // LogicMonitor Access Key
    private static final String LOGICMONITOR_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // SolarWinds API Token
    private static final String SOLARWINDS_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // ManageEngine API Key
    private static final String MANAGEENGINE_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Zabbix API Token
    private static final String ZABBIX_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Nagios API Token
    private static final String NAGIOS_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Icinga API Token
    private static final String ICINGA_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Prometheus Alertmanager Token
    private static final String ALERTMANAGER_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Thanos Receive Token
    private static final String THANOS_RECEIVE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Cortex Write Token
    private static final String CORTEX_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Mimir Write Token
    private static final String MIMIR_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Loki Write Token
    private static final String LOKI_WRITE_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE";

    // Tempo Write Token
    private static final String TEMPO_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Pyroscope Write Token
    private static final String PYROSCOPE_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Parca Write Token
    private static final String PARCA_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Jaeger Write Token
    private static final String JAEGER_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Zipkin Write Token
    private static final String ZIPKIN_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Honeycomb Write Token
    private static final String HONEYCOMB_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Lightstep Write Token
    private static final String LIGHTSTEP_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Datadog Write Token
    private static final String DATADOG_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // AppDynamics Write Token
    private static final String APPDYNAMICS_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Dynatrace Write Token
    private static final String DYNATRACE_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Splunk Write Token
    private static final String SPLUNK_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Logz.io Write Token
    private static final String LOGZIO_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Sumo Logic Write Token
    private static final String SUMOLOGIC_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // LogicMonitor Write Token
    private static final String LOGICMONITOR_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // SolarWinds Write Token
    private static final String SOLARWINDS_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // ManageEngine Write Token
    private static final String MANAGEENGINE_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Zabbix Write Token
    private static final String ZABBIX_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Nagios Write Token
    private static final String NAGIOS_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Icinga Write Token
    private static final String ICINGA_WRITE_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // This class is intentionally never instantiated or used in production code
    private HardcodedSecretsDemo() {
        throw new UnsupportedOperationException("This class is for security testing only");
    }
}
