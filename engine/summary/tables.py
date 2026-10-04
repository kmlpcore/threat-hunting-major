"""Summary table definitions (plan.md section 3.4).

Each table is built per (source, day) from that day's raw ECS rows, registered in
DuckDB as `raw`. Column names in raw are ECS dotted names, so they are quoted.
Every output row also gets `day`, `policy_version` and `built_at`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SummaryTable:
    name: str
    source: str
    grain: str
    sql: str

    @property
    def identifier(self) -> str:
        return f"summary.{self.name}"


TABLES: dict[str, SummaryTable] = {t.name: t for t in [
    SummaryTable("auth_hourly", "windows_security", "user x host x hour", """
        SELECT date_trunc('hour', "@timestamp") AS hour,
               "user.name" AS user_name, any_value("user.id") AS user_id, "host.name" AS host_name,
               count(*) FILTER (WHERE "event.outcome" = 'success') AS success,
               count(*) FILTER (WHERE "event.outcome" = 'failure') AS failure,
               count(DISTINCT "source.ip") AS distinct_src_ips,
               count(DISTINCT "winlog.logon.type") AS distinct_logon_types,
               list_distinct(list("winlog.logon.type") FILTER (WHERE "winlog.logon.type" IS NOT NULL)) AS logon_types,
               list_distinct(list("source.ip") FILTER (WHERE "source.ip" IS NOT NULL)) AS src_ips
        FROM raw
        WHERE list_contains("event.category", 'authentication') AND "event.action" <> 'logged-out'
        GROUP BY ALL"""),

    SummaryTable("user_daily", "windows_security", "user x day", """
        SELECT "user.name" AS user_name, any_value("user.id") AS user_id,
               count(DISTINCT "source.ip") AS distinct_src_ips,
               count(DISTINCT "host.name") AS distinct_hosts,
               list_distinct(list("host.name") FILTER (WHERE "host.name" IS NOT NULL)) AS hosts,
               min("@timestamp") AS first_seen, max("@timestamp") AS last_seen,
               count(*) FILTER (WHERE "event.code" IN ('4672', '4728', '4732')) AS privileged_actions,
               count(*) FILTER (WHERE "event.outcome" = 'failure') AS failed_logons,
               count(*) FILTER (WHERE "event.action" = 'logged-in') AS logons
        FROM raw WHERE "user.name" IS NOT NULL
        GROUP BY "user.name\""""),

    SummaryTable("process_daily", "sysmon", "host x process x parent x day", """
        WITH p AS (
            SELECT "host.name" AS host_name, lower("process.name") AS process_name,
                   lower("process.parent.name") AS parent_name,
                   count(*) AS exec_count,
                   count(DISTINCT md5("process.command_line")) AS distinct_cmdline_hashes,
                   list_distinct(list("user.name") FILTER (WHERE "user.name" IS NOT NULL)) AS users,
                   any_value("process.hash.sha256") AS process_hash,
                   any_value("process.executable") AS executable,
                   max(length("process.command_line")) AS max_cmdline_len
            FROM raw GROUP BY ALL)
        SELECT *, 1.0 - (count(DISTINCT host_name) OVER (PARTITION BY process_name))::DOUBLE
                        / (SELECT count(DISTINCT "host.name") FROM raw) AS rarity_score
        FROM p"""),

    SummaryTable("network_hourly", "zeek_conn", "host x dest x port x hour", """
        SELECT date_trunc('hour', "@timestamp") AS hour, "host.name" AS host_name,
               "destination.ip" AS dest_ip, "destination.port" AS dest_port,
               any_value("network.transport") AS transport, any_value("network.direction") AS direction,
               count(*) AS conn_count, count(DISTINCT "source.ip") AS distinct_src_ips,
               sum(coalesce("source.bytes", 0)) AS bytes_out, sum(coalesce("destination.bytes", 0)) AS bytes_in,
               count(*) FILTER (WHERE "event.outcome" = 'failure') AS failed_conns
        FROM raw GROUP BY ALL"""),

    SummaryTable("dns_daily", "zeek_dns", "host x registered domain x day", """
        SELECT "host.name" AS host_name,
               coalesce("dns.question.registered_domain", "dns.question.name") AS registered_domain,
               count(*) AS query_count,
               avg(("dns.response_code" = 'NXDOMAIN')::INTEGER)::DOUBLE AS nxdomain_ratio,
               avg(entropy(coalesce("dns.question.subdomain", ''))) AS avg_label_entropy,
               max(length(coalesce("dns.question.subdomain", ''))) AS max_subdomain_len,
               count(DISTINCT "dns.question.subdomain") AS distinct_subdomains,
               list_distinct(list("dns.question.type") FILTER (WHERE "dns.question.type" IS NOT NULL)) AS qtypes
        FROM raw GROUP BY ALL"""),

    SummaryTable("web_daily", "proxy", "user x host x registered domain x day", """
        SELECT "user.name" AS user_name, "host.name" AS host_name,
               coalesce("url.registered_domain", "url.domain") AS registered_domain,
               count(*) AS requests,
               sum(coalesce("http.request.bytes", 0)) AS bytes_out,
               sum(coalesce("http.response.bytes", 0)) AS bytes_in,
               count(*) FILTER (WHERE "http.request.method" IN ('POST', 'PUT')) AS uploads,
               count(*) FILTER (WHERE "http.response.status_code" >= 400) AS errors,
               list_distinct(list("user_agent.original") FILTER (WHERE "user_agent.original" IS NOT NULL)) AS user_agents
        FROM raw GROUP BY ALL"""),

    SummaryTable("cloud_api_daily", "cloudtrail", "principal x service x action x day", """
        SELECT "user.name" AS principal, "cloud.service.name" AS service, "event.action" AS action,
               count(*) AS calls, count(*) FILTER (WHERE "event.outcome" = 'failure') AS errors,
               count(DISTINCT "cloud.region") AS distinct_regions,
               list_distinct(list("cloud.region") FILTER (WHERE "cloud.region" IS NOT NULL)) AS regions,
               list_distinct(list("source.ip") FILTER (WHERE "source.ip" IS NOT NULL)) AS src_ips
        FROM raw GROUP BY ALL"""),

    SummaryTable("metrics_hourly", "host_metrics", "host x metric x hour", """
        WITH m AS (
            SELECT date_trunc('hour', "@timestamp") AS hour, "host.name" AS host_name, 'cpu.usage' AS metric,
                   "host.cpu.usage"::DOUBLE AS v FROM raw
            UNION ALL SELECT date_trunc('hour', "@timestamp"), "host.name", 'memory.used.pct',
                   "system.memory.actual.used.pct"::DOUBLE FROM raw
            UNION ALL SELECT date_trunc('hour', "@timestamp"), "host.name", 'network.egress.bytes',
                   "host.network.egress.bytes"::DOUBLE FROM raw
            UNION ALL SELECT date_trunc('hour', "@timestamp"), "host.name", 'network.ingress.bytes',
                   "host.network.ingress.bytes"::DOUBLE FROM raw)
        SELECT hour, host_name, metric, quantile_cont(v, 0.5) AS p50, quantile_cont(v, 0.95) AS p95,
               max(v) AS max, count(*) AS samples
        FROM m WHERE v IS NOT NULL GROUP BY ALL"""),
]}

HIGH_VALUE = "summary.high_value_events"


def tables_for_source(source: str) -> list[SummaryTable]:
    return [t for t in TABLES.values() if t.source == source]


def source_of_table(name: str) -> str:
    return TABLES[name].source
