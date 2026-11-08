"""Active CTU-only datasets and dashboard definitions. No historical source labels."""
import json
from uuid import NAMESPACE_URL,uuid5

def uid(name: str) -> str:
    return str(uuid5(NAMESPACE_URL, "dns-security-analytics/ctu/superset/" + name))


def metric(name: str, expression: str, fmt: str = ",.0f") -> dict:
    return {"metric_name": name, "verbose_name": name, "expression": expression,
            "d3format": fmt, "description": "Project dashboard metric; evaluated at the dataset's documented grain."}


def condition(column: str,value: str) -> dict:
    return {"expressionType":"SIMPLE","subject":column,"operator":"==","comparator":value,
            "clause":"WHERE","sqlExpression":None,"isExtra":False,"isNew":False}


def datasets() -> dict:
    def data(table: str,metrics: list, time: str | None = None) -> dict:
        return {"table_name":table,"main_dttm_col":time,"description":"Live CTU-only facts; capture identity is provenance, not a maliciousness label.",
                "columns":[],"required":["capture_name","source_ip"],"metrics":metrics}
    return {
     "events":data("vw_dns_event_analysis",[metric("DNS events","COUNT(*)"),metric("NXDOMAIN ratio","COUNT(*) FILTER(WHERE response_code=3)::numeric/NULLIF(COUNT(*),0)",".2%")],"event_timestamp"),
     "windows":data("vw_dns_window_analysis",[metric("Windows","COUNT(*)"),metric("Window queries","MAX(query_count)"),metric("Window NX ratio","MAX(nxdomain_ratio)",".1%"),metric("Window mean entropy","MAX(avg_entropy)",".3f"),metric("Window mean length","MAX(avg_domain_length)",".2f")],"window_start"),
     "alerts":data("vw_dns_alert_analysis",[metric("Alerts","COUNT(*)")],"window_start"),
     "captures":data("vw_ctu_capture_sources",[metric("Events","SUM(dns_events)"),metric("Capture windows","SUM(total_windows)"),metric("NX ratio","SUM(nxdomain_events)::numeric/NULLIF(SUM(dns_events),0)",".2%"),metric("Alert records","SUM(alert_records)"),metric("Alerting windows","SUM(alerting_windows)")]),
     "detectors":data("vw_ctu_detector_sources",[metric("Alerting windows","SUM(alerting_windows)"),metric("Capture windows","SUM(total_windows)"),metric("Activation rate (%)","100.0*SUM(alerting_windows)/NULLIF(SUM(total_windows),0)",".2f")]),
     "features":data("vw_ctu_feature_samples",[metric("Samples","COUNT(*)"),metric("Minimum","MIN(value)",".4f"),metric("Median","percentile_cont(0.5) WITHIN GROUP(ORDER BY value)",".4f"),metric("p95","percentile_cont(0.95) WITHIN GROUP(ORDER BY value)",".4f"),metric("Maximum","MAX(value)",".4f"),metric("Mean","AVG(value)",".4f")])}


def charts() -> list[dict]:
    def c(key,title,dataset,viz,**form):return {"key":key,"title":title,"dataset":dataset,"viz":viz,"form":form}
    return [
     c("traffic-events","CTU DNS events","events","big_number_total",metric="DNS events"),
     c("traffic-nx","NXDOMAIN ratio · all selected events","events","big_number_total",metric="NXDOMAIN ratio",y_axis_format=".2%"),
     c("traffic-captures","DNS events by public capture","events","echarts_timeseries_bar",x_axis="capture_name",metrics=["DNS events"]),
     c("traffic-rcode","Response codes · Unknown is not success","events","echarts_timeseries_bar",x_axis="response_code_name",groupby=["capture_name"],metrics=["DNS events"],show_legend=True),
     c("traffic-types","Query types","events","echarts_timeseries_bar",x_axis="query_type_name",groupby=["capture_name"],metrics=["DNS events"],show_legend=True),
     c("traffic-domains","Top queried names · inert strings","events","echarts_timeseries_bar",x_axis="query",metrics=["DNS events"],orientation="horizontal",row_limit=10),
     c("traffic-sources","DNS events by source IP","events","echarts_timeseries_bar",x_axis="source_ip",metrics=["DNS events"],orientation="horizontal"),
     c("traffic-activity","Activity distribution · events per source-minute","windows","echarts_timeseries_bar",x_axis="query_count",groupby=["capture_name"],metrics=["Windows"],show_legend=True),
     c("security-total","Explainable alert records","alerts","big_number_total",metric="Alerts",subheader="Overlapping types retained"),
     c("security-types","Alerts by detector","alerts","echarts_timeseries_bar",x_axis="alert_type",metrics=["Alerts"],orientation="horizontal"),
     c("security-severity","Severity distribution","alerts","pie",groupby=["severity"],metric="Alerts",donut=True,show_labels=True,show_legend=True,labels_outside=False,label_type="key_value"),
     c("security-captures","Alert records by capture","alerts","echarts_timeseries_bar",x_axis="capture_name",metrics=["Alerts"]),
     c("security-sources","Source IPs with alerts","alerts","echarts_timeseries_bar",x_axis="source_ip",metrics=["Alerts"],orientation="horizontal"),
     c("security-nx-volume","NXDOMAIN ratio vs query volume · one point per window","windows","bubble_v2",entity="window_key",series="capture_name",x="Window queries",y="Window NX ratio",size="Window queries",show_legend=True,logXAxis=False,logYAxis=False,max_bubble_size="15",y_axis_format=".1%",x_axis_label="Events / minute",y_axis_label="NXDOMAIN ratio",y_axis_title_margin=50),
     c("security-entropy-length","Mean entropy vs query length · one point per window","windows","bubble_v2",entity="window_key",series="capture_name",x="Window mean length",y="Window mean entropy",size="Window queries",show_legend=True,logXAxis=False,logYAxis=False,max_bubble_size="15",y_axis_format=".3f",x_axis_label="Mean length",y_axis_label="Entropy (bits)",y_axis_title_margin=50),
     c("security-details","Alert evidence · observed values and satisfied thresholds","alerts","table",query_mode="raw",all_columns=["capture_name","source_ip","window_start","alert_type","severity","metrics_evidence","threshold_evidence","config_sha256"],page_length=5,include_search=True,order_by_cols=[json.dumps(["window_start",False])]),
     c("comparison-overview","CTU capture comparison · rows are not event labels","captures","table",query_mode="aggregate",groupby=["capture_name"],metrics=["Events","Capture windows","NX ratio","Alert records","Alerting windows"],page_length=5),
     c("comparison-rates","Descriptive detector activation · percent of capture windows","detectors","echarts_timeseries_bar",x_axis="detector",groupby=["capture_name"],metrics=["Activation rate (%)"],show_legend=True,y_axis_format=".2f",y_axis_bounds=[0,100],truncateYAxis=True),
     c("comparison-counts","Absolute alerting-window counts · overlaps retained","detectors","table",query_mode="aggregate",groupby=["capture_name","detector"],metrics=["Alerting windows","Capture windows","Activation rate (%)"],page_length=8),
     c("comparison-features","Actual window feature distributions · ratios 0–1","features","table",query_mode="aggregate",groupby=["feature","capture_name"],metrics=["Samples","Minimum","Median","p95","Maximum","Mean"],page_length=12),
     c("comparison-examples","Representative high-entropy windows · not truth labels","windows","table",query_mode="raw",all_columns=["capture_name","source_ip","window_start","query_count","unique_domain_count","nxdomain_ratio","avg_domain_length","avg_entropy","alert_count"],page_length=8,order_by_cols=[json.dumps(["avg_entropy",False])])]

NOTICE="""## CTU / DNS SECURITY ANALYTICS
Public capture identity does not label every event or window as benign/malicious. Results are descriptive rule activation, not precision/recall/F1 or confirmed true/false positives. Original UTC timestamps, including 1970, remain unchanged.

Thresholds retain their historical controlled synthetic-calibration origin; no synthetic data or evaluation participates in this application. CTU was not used to retune them.
"""
DASHBOARDS=[
 {"slug":"dns-traffic-overview","title":"DNS Traffic Overview","prefix":"traffic-","notice":NOTICE,
  "rows":[[("traffic-events",4,22),("traffic-nx",4,22),("traffic-captures",4,22)],[("traffic-rcode",6,38),("traffic-types",6,38)],[("traffic-domains",6,48),("traffic-sources",6,48)],[("traffic-activity",12,42)]]},
 {"slug":"dns-security-anomaly-analysis","title":"DNS Security & Anomaly Analysis","prefix":"security-","notice":NOTICE,
  "rows":[[("security-total",3,32),("security-types",6,32),("security-severity",3,32)],[("security-captures",6,34),("security-sources",6,34)],[("security-nx-volume",6,45),("security-entropy-length",6,45)],[("security-details",12,65)]]},
 {"slug":"ctu-security-comparison","title":"CTU Security Comparison","prefix":"comparison-","notice":NOTICE,
  "rows":[[("comparison-overview",12,30)],[("comparison-rates",12,43)],[("comparison-counts",12,50)],[("comparison-features",12,60)],[("comparison-examples",12,48)]]}]

CSS = """
.dashboard-content { background: #f2f5fa; }
.dashboard-component-chart-holder { border: 1px solid #dfe6ef; border-radius: 12px; box-shadow: 0 3px 12px rgba(22,47,76,.045); }
.dashboard-component-header { color: #18334f; font-weight: 600; }
.dashboard-markdown { border-radius: 12px; }
.dashboard-markdown .dashboard-component { background: #18334f; color: #eef5ff; padding: 14px 20px; box-sizing: border-box; }
.dashboard-markdown h2 { color: #ffffff; font-size: 19px; letter-spacing: .07em; margin: 0 0 8px; }
.dashboard-markdown p { font-size: 13px; margin: 0; line-height: 1.6; }
"""
