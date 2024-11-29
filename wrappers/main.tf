module "wrapper" {
  source = "../."

  for_each = var.items

  auto_groups = try(each.value.auto_groups, var.defaults.auto_groups, {
    activemq = {
      ingress_rules     = ["activemq-5671-tcp", "activemq-8883-tcp", "activemq-61614-tcp", "activemq-61617-tcp", "activemq-61619-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    alertmanager = {
      ingress_rules     = ["alertmanager-9093-tcp", "alertmanager-9094-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    carbon-relay-ng = {
      ingress_rules     = ["carbon-line-in-tcp", "carbon-line-in-udp", "carbon-pickle-tcp", "carbon-pickle-udp", "carbon-gui-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    cassandra = {
      ingress_rules     = ["cassandra-clients-tcp", "cassandra-thrift-clients-tcp", "cassandra-jmx-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    consul = {
      ingress_rules     = ["consul-tcp", "consul-grpc-tcp", "consul-grpc-tcp-tls", "consul-webui-http-tcp", "consul-webui-https-tcp", "consul-dns-tcp", "consul-dns-udp", "consul-serf-lan-tcp", "consul-serf-lan-udp", "consul-serf-wan-tcp", "consul-serf-wan-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    dax-cluster = {
      ingress_rules     = ["dax-cluster-unencrypted-tcp", "dax-cluster-encrypted-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    docker-swarm = {
      ingress_rules     = ["docker-swarm-mngmt-tcp", "docker-swarm-node-tcp", "docker-swarm-node-udp", "docker-swarm-overlay-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    etcd = {
      ingress_rules     = ["etcd-client-tcp", "etcd-peer-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    elasticsearch = {
      ingress_rules     = ["elasticsearch-rest-tcp", "elasticsearch-java-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    grafana = {
      ingress_rules     = ["grafana-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    graphite-statsd = {
      ingress_rules     = ["graphite-webui", "graphite-2003-tcp", "graphite-2004-tcp", "graphite-2023-tcp", "graphite-2024-tcp", "graphite-8080-tcp", "graphite-8125-tcp", "graphite-8125-udp", "graphite-8126-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    http-80 = {
      ingress_rules     = ["http-80-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    http-8080 = {
      ingress_rules     = ["http-8080-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    https-443 = {
      ingress_rules     = ["https-443-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    https-8443 = {
      ingress_rules     = ["https-8443-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    ipsec-500 = {
      ingress_rules     = ["ipsec-500-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    ipsec-4500 = {
      ingress_rules     = ["ipsec-4500-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    kafka = {
      ingress_rules     = ["kafka-broker-tcp", "kafka-broker-tls-tcp", "kafka-broker-tls-public-tcp", "kafka-broker-sasl-scram-tcp", "kafka-broker-sasl-scram-tcp", "kafka-broker-sasl-iam-tcp", "kafka-broker-sasl-iam-public-tcp", "kafka-jmx-exporter-tcp", "kafka-node-exporter-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    kubernetes-api = {
      ingress_rules     = ["kubernetes-api-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    kibana = {
      ingress_rules     = ["kibana-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    ldap = {
      ingress_rules     = ["ldap-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    ldaps = {
      ingress_rules     = ["ldaps-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    logstash = {
      ingress_rules     = ["logstash-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    loki = {
      ingress_rules     = ["loki-grafana", "loki-grafana-grpc"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    memcached = {
      ingress_rules     = ["memcached-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    minio = {
      ingress_rules     = ["minio-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    mongodb = {
      ingress_rules     = ["mongodb-27017-tcp", "mongodb-27018-tcp", "mongodb-27019-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    mysql = {
      ingress_rules     = ["mysql-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    mssql = {
      ingress_rules     = ["mssql-tcp", "mssql-udp", "mssql-analytics-tcp", "mssql-broker-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    nfs = {
      ingress_rules     = ["nfs-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    nomad = {
      ingress_rules     = ["nomad-http-tcp", "nomad-rpc-tcp", "nomad-serf-tcp", "nomad-serf-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    openvpn = {
      ingress_rules     = ["openvpn-udp", "openvpn-tcp", "openvpn-https-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    postgresql = {
      ingress_rules     = ["postgresql-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    oracle-db = {
      ingress_rules     = ["oracle-db-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    ntp = {
      ingress_rules     = ["ntp-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    puppet = {
      ingress_rules     = ["puppet-tcp", "puppetdb-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    prometheus = {
      ingress_rules     = ["prometheus-http-tcp", "prometheus-pushgateway-http-tcp", "prometheus-node-exporter-http-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    promtail = {
      ingress_rules     = ["promtail-http"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    rabbitmq = {
      ingress_rules     = ["rabbitmq-4369-tcp", "rabbitmq-5671-tcp", "rabbitmq-5672-tcp", "rabbitmq-15672-tcp", "rabbitmq-25672-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    rdp = {
      ingress_rules     = ["rdp-tcp", "rdp-udp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    redis = {
      ingress_rules     = ["redis-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    redshift = {
      ingress_rules     = ["redshift-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    smtp = {
      ingress_rules     = ["smtp-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    smtp-submission = {
      ingress_rules     = ["smtp-submission-587-tcp", "smtp-submission-2587-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    smtps = {
      ingress_rules     = ["smtps-465-tcp", "smtps-2465-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    solr = {
      ingress_rules     = ["solr-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    splunk = {
      ingress_rules     = ["splunk-indexer-tcp", "splunk-web-tcp", "splunk-splunkd-tcp", "splunk-hec-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    squid = {
      ingress_rules     = ["squid-proxy-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    ssh = {
      ingress_rules     = ["ssh-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    storm = {
      ingress_rules     = ["storm-nimbus-tcp", "storm-ui-tcp", "storm-supervisor-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    vault = {
      ingress_rules     = ["vault-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    wazuh = {
      ingress_rules     = ["wazuh-server-agent-connection-tcp", "wazuh-server-agent-connection-udp", "wazuh-server-agent-enrollment", "wazuh-server-agent-cluster-daemon", "wazuh-server-syslog-collector-tcp", "wazuh-server-syslog-collector-udp", "wazuh-server-restful-api", "wazuh-indexer-restful-api", "wazuh-dashboard", ]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    web = {
      ingress_rules     = ["http-80-tcp", "http-8080-tcp", "https-443-tcp", "web-jmx-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    winrm = {
      ingress_rules     = ["winrm-http-tcp", "winrm-https-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    zabbix = {
      ingress_rules     = ["zabbix-server", "zabbix-proxy", "zabbix-agent"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    zipkin = {
      ingress_rules     = ["zipkin-admin-tcp", "zipkin-admin-query-tcp", "zipkin-admin-web-tcp", "zipkin-query-tcp", "zipkin-web-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
    zookeeper = {
      ingress_rules     = ["zookeeper-2181-tcp", "zookeeper-2182-tls-tcp", "zookeeper-2888-tcp", "zookeeper-3888-tcp", "zookeeper-jmx-tcp"]
      ingress_with_self = ["all-all"]
      egress_rules      = ["all-all"]
    }
  })
  computed_egress_rules                                    = try(each.value.computed_egress_rules, var.defaults.computed_egress_rules, [])
  computed_egress_with_cidr_blocks                         = try(each.value.computed_egress_with_cidr_blocks, var.defaults.computed_egress_with_cidr_blocks, [])
  computed_egress_with_ipv6_cidr_blocks                    = try(each.value.computed_egress_with_ipv6_cidr_blocks, var.defaults.computed_egress_with_ipv6_cidr_blocks, [])
  computed_egress_with_prefix_list_ids                     = try(each.value.computed_egress_with_prefix_list_ids, var.defaults.computed_egress_with_prefix_list_ids, [])
  computed_egress_with_self                                = try(each.value.computed_egress_with_self, var.defaults.computed_egress_with_self, [])
  computed_egress_with_source_security_group_id            = try(each.value.computed_egress_with_source_security_group_id, var.defaults.computed_egress_with_source_security_group_id, [])
  computed_ingress_rules                                   = try(each.value.computed_ingress_rules, var.defaults.computed_ingress_rules, [])
  computed_ingress_with_cidr_blocks                        = try(each.value.computed_ingress_with_cidr_blocks, var.defaults.computed_ingress_with_cidr_blocks, [])
  computed_ingress_with_ipv6_cidr_blocks                   = try(each.value.computed_ingress_with_ipv6_cidr_blocks, var.defaults.computed_ingress_with_ipv6_cidr_blocks, [])
  computed_ingress_with_prefix_list_ids                    = try(each.value.computed_ingress_with_prefix_list_ids, var.defaults.computed_ingress_with_prefix_list_ids, [])
  computed_ingress_with_self                               = try(each.value.computed_ingress_with_self, var.defaults.computed_ingress_with_self, [])
  computed_ingress_with_source_security_group_id           = try(each.value.computed_ingress_with_source_security_group_id, var.defaults.computed_ingress_with_source_security_group_id, [])
  create                                                   = try(each.value.create, var.defaults.create, true)
  create_sg                                                = try(each.value.create_sg, var.defaults.create_sg, true)
  create_timeout                                           = try(each.value.create_timeout, var.defaults.create_timeout, "10m")
  delete_timeout                                           = try(each.value.delete_timeout, var.defaults.delete_timeout, "15m")
  description                                              = try(each.value.description, var.defaults.description, "Security Group managed by Terraform")
  egress_cidr_blocks                                       = try(each.value.egress_cidr_blocks, var.defaults.egress_cidr_blocks, ["0.0.0.0/0"])
  egress_ipv6_cidr_blocks                                  = try(each.value.egress_ipv6_cidr_blocks, var.defaults.egress_ipv6_cidr_blocks, ["::/0"])
  egress_prefix_list_ids                                   = try(each.value.egress_prefix_list_ids, var.defaults.egress_prefix_list_ids, [])
  egress_rules                                             = try(each.value.egress_rules, var.defaults.egress_rules, [])
  egress_with_cidr_blocks                                  = try(each.value.egress_with_cidr_blocks, var.defaults.egress_with_cidr_blocks, [])
  egress_with_ipv6_cidr_blocks                             = try(each.value.egress_with_ipv6_cidr_blocks, var.defaults.egress_with_ipv6_cidr_blocks, [])
  egress_with_prefix_list_ids                              = try(each.value.egress_with_prefix_list_ids, var.defaults.egress_with_prefix_list_ids, [])
  egress_with_self                                         = try(each.value.egress_with_self, var.defaults.egress_with_self, [])
  egress_with_source_security_group_id                     = try(each.value.egress_with_source_security_group_id, var.defaults.egress_with_source_security_group_id, [])
  ingress_cidr_blocks                                      = try(each.value.ingress_cidr_blocks, var.defaults.ingress_cidr_blocks, [])
  ingress_ipv6_cidr_blocks                                 = try(each.value.ingress_ipv6_cidr_blocks, var.defaults.ingress_ipv6_cidr_blocks, [])
  ingress_prefix_list_ids                                  = try(each.value.ingress_prefix_list_ids, var.defaults.ingress_prefix_list_ids, [])
  ingress_rules                                            = try(each.value.ingress_rules, var.defaults.ingress_rules, [])
  ingress_with_cidr_blocks                                 = try(each.value.ingress_with_cidr_blocks, var.defaults.ingress_with_cidr_blocks, [])
  ingress_with_ipv6_cidr_blocks                            = try(each.value.ingress_with_ipv6_cidr_blocks, var.defaults.ingress_with_ipv6_cidr_blocks, [])
  ingress_with_prefix_list_ids                             = try(each.value.ingress_with_prefix_list_ids, var.defaults.ingress_with_prefix_list_ids, [])
  ingress_with_self                                        = try(each.value.ingress_with_self, var.defaults.ingress_with_self, [])
  ingress_with_source_security_group_id                    = try(each.value.ingress_with_source_security_group_id, var.defaults.ingress_with_source_security_group_id, [])
  name                                                     = try(each.value.name, var.defaults.name, null)
  number_of_computed_egress_rules                          = try(each.value.number_of_computed_egress_rules, var.defaults.number_of_computed_egress_rules, 0)
  number_of_computed_egress_with_cidr_blocks               = try(each.value.number_of_computed_egress_with_cidr_blocks, var.defaults.number_of_computed_egress_with_cidr_blocks, 0)
  number_of_computed_egress_with_ipv6_cidr_blocks          = try(each.value.number_of_computed_egress_with_ipv6_cidr_blocks, var.defaults.number_of_computed_egress_with_ipv6_cidr_blocks, 0)
  number_of_computed_egress_with_prefix_list_ids           = try(each.value.number_of_computed_egress_with_prefix_list_ids, var.defaults.number_of_computed_egress_with_prefix_list_ids, 0)
  number_of_computed_egress_with_self                      = try(each.value.number_of_computed_egress_with_self, var.defaults.number_of_computed_egress_with_self, 0)
  number_of_computed_egress_with_source_security_group_id  = try(each.value.number_of_computed_egress_with_source_security_group_id, var.defaults.number_of_computed_egress_with_source_security_group_id, 0)
  number_of_computed_ingress_rules                         = try(each.value.number_of_computed_ingress_rules, var.defaults.number_of_computed_ingress_rules, 0)
  number_of_computed_ingress_with_cidr_blocks              = try(each.value.number_of_computed_ingress_with_cidr_blocks, var.defaults.number_of_computed_ingress_with_cidr_blocks, 0)
  number_of_computed_ingress_with_ipv6_cidr_blocks         = try(each.value.number_of_computed_ingress_with_ipv6_cidr_blocks, var.defaults.number_of_computed_ingress_with_ipv6_cidr_blocks, 0)
  number_of_computed_ingress_with_prefix_list_ids          = try(each.value.number_of_computed_ingress_with_prefix_list_ids, var.defaults.number_of_computed_ingress_with_prefix_list_ids, 0)
  number_of_computed_ingress_with_self                     = try(each.value.number_of_computed_ingress_with_self, var.defaults.number_of_computed_ingress_with_self, 0)
  number_of_computed_ingress_with_source_security_group_id = try(each.value.number_of_computed_ingress_with_source_security_group_id, var.defaults.number_of_computed_ingress_with_source_security_group_id, 0)
  putin_khuylo                                             = try(each.value.putin_khuylo, var.defaults.putin_khuylo, true)
  revoke_rules_on_delete                                   = try(each.value.revoke_rules_on_delete, var.defaults.revoke_rules_on_delete, false)
  rules                                                    = try(each.value.rules, var.defaults.rules, {})
  security_group_id                                        = try(each.value.security_group_id, var.defaults.security_group_id, null)
  tags                                                     = try(each.value.tags, var.defaults.tags, {})
  use_name_prefix                                          = try(each.value.use_name_prefix, var.defaults.use_name_prefix, true)
  vpc_id                                                   = try(each.value.vpc_id, var.defaults.vpc_id, null)
}
