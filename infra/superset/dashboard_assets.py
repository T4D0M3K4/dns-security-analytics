"""Supported REST-only dashboard lifecycle for the pinned Superset 6.1.0 instance.

Run inside superset-init with this directory mounted read-only. Credentials are
read from its environment and never written to assets or logs.
"""

import argparse
import io
import json
import os
from pathlib import Path
from urllib.parse import quote
import zipfile

import requests
import yaml

from dashboard_definitions import CSS, DASHBOARDS, charts, datasets, uid


class API:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.session = requests.Session()
        result = self.call("POST", "/api/v1/security/login", json={
            "username": os.environ["SUPERSET_ADMIN_USER"], "password": os.environ["SUPERSET_ADMIN_PASSWORD"], "provider": "db"})
        self.session.headers["Authorization"] = "Bearer " + result["access_token"]
        self.session.headers["X-CSRFToken"] = self.call("GET", "/api/v1/security/csrf_token/")["result"]
        self.spec = self.call("GET", "/api/v1/_openapi")
        for name in ("DatasetRestApi.post", "DatasetRestApi.put", "ChartRestApi.post", "DashboardRestApi.put"):
            if name not in self.spec["components"]["schemas"]:
                raise RuntimeError("Unexpected Superset API schema: " + name)

    def call(self, method: str, path: str, **kwargs) -> dict:
        response = self.session.request(method, self.base + path, timeout=120, **kwargs)
        if not response.ok:
            # Only API validation messages, never login payloads or connection exports.
            raise RuntimeError(f"{method} {path}: HTTP {response.status_code}: {response.text[:700]}")
        return response.json()

    def listing(self, kind: str) -> list[dict]:
        result, page = [], 0
        while True:
            data = self.call("GET", f"/api/v1/{kind}/", params={"q": json.dumps({"page_size": 100, "page": page})})
            result.extend(data["result"])
            if len(result) >= data["count"]:
                return result
            page += 1

    def upsert(self, kind: str, identifier: str, payload: dict) -> int:
        existing = next((item for item in self.listing(kind) if item.get("uuid") == identifier), None)
        if existing:
            self.call("PUT", f"/api/v1/{kind}/{existing['id']}", json=payload)
            return existing["id"]
        return self.call("POST", f"/api/v1/{kind}/", json={**payload, "uuid": identifier})["id"]


def prepare_datasets(api: API, definitions: dict | None = None, update_connection: bool = True) -> dict[str, int]:
    databases = api.listing("database")
    database = next(item for item in databases if item["database_name"] == "DNS Security Analytics (read-only)")
    if update_connection:
        api.call("PUT", f"/api/v1/database/{database['id']}", json={
            "extra": json.dumps({"engine_params": {"connect_args": {"options": "-c timezone=UTC"}}})})
    result = {}
    for key, definition in (datasets() if definitions is None else definitions).items():
        identifier = uid("dataset/" + key)
        current = next((item for item in api.listing("dataset") if item.get("uuid") == identifier), None)
        if current is None:
            # Reuse an already registered physical reporting view instead of duplicating it.
            current = next((item for item in api.listing("dataset") if not definition.get("sql")
                            and item["table_name"] == definition["table_name"] and item.get("schema") == "reporting"
                            and item.get("database", {}).get("id") == database["id"]), None)
        if current is None:
            payload = {"database": database["id"], "schema": "reporting", "table_name": definition["table_name"], "uuid": identifier}
            if definition.get("sql"):
                payload["sql"] = definition["sql"]
            dataset_id = api.call("POST", "/api/v1/dataset/", json=payload)["id"]
        else:
            dataset_id = current["id"]
        detail = api.call("GET", f"/api/v1/dataset/{dataset_id}")["result"]
        columns = {col["column_name"]: {k: v for k, v in col.items() if k in
            ("id", "column_name", "type", "expression", "is_dttm", "groupby", "filterable", "is_active", "verbose_name")}
                   for col in detail["columns"]}
        missing = set(definition["required"]) - set(columns)
        if missing:
            raise RuntimeError(f"Live dataset {key} missing columns: {sorted(missing)}")
        for col in definition["columns"]:
            columns[col["column_name"]] = {**columns.get(col["column_name"], {}), **col}
        metrics = {m["metric_name"]: {k: v for k, v in m.items() if k in
            ("id", "metric_name", "expression", "d3format", "verbose_name", "description")}
                   for m in detail.get("metrics", [])}
        for metric in definition["metrics"]:
            metrics[metric["metric_name"]] = {**metrics.get(metric["metric_name"], {}), **metric}
        api.call("PUT", f"/api/v1/dataset/{dataset_id}", json={
            "uuid": identifier, "description": definition["description"],
            "main_dttm_col": definition["main_dttm_col"], "columns": list(columns.values()), "metrics": list(metrics.values())})
        result[key] = dataset_id
        print(f"Dataset {key}: id={dataset_id}")
    return result


def query_context(dataset_id: int, form: dict) -> dict:
    viz = form["viz_type"]
    q = {"filters": [{"col": f["subject"], "op": f["operator"], "val": f["comparator"]} for f in form["adhoc_filters"]],
         "time_range": "No filter", "extras": {"having": "", "where": ""}, "row_limit": form["row_limit"],
         "granularity": form.get("granularity_sqla"), "is_timeseries": False, "columns": [], "metrics": []}
    if viz == "big_number_total":
        q["metrics"] = [form["metric"]]
    elif viz == "pie":
        q["metrics"], q["columns"] = [form["metric"]], form["groupby"]
    elif viz == "bubble_v2":
        q["metrics"] = list(dict.fromkeys([form["x"], form["y"], form["size"]]))
        q["columns"] = [form["entity"], form["series"]]
    elif viz == "table":
        if form["query_mode"] == "raw":
            q["columns"] = form["all_columns"]
            q["orderby"] = [json.loads(value) for value in form.get("order_by_cols", [json.dumps(["window_start",False])])]
        else:
            q["columns"], q["metrics"] = form["groupby"], form["metrics"]
    else:
        q["columns"], q["metrics"] = [form["x_axis"], *form["groupby"]], form["metrics"]
        if form["x_axis"] == "window_start":
            q["columns"] = [{"expressionType": "SQL", "sqlExpression": "window_start", "label": "window_start", "columnType": "BASE_AXIS", "timeGrain": "PT1M"}]
            q["extras"]["time_grain_sqla"] = "PT1M"
            q["orderby"] = [["window_start", True]]
        else:
            q["orderby"] = [[form["metrics"][0], False]]
    return {"datasource": {"id": dataset_id, "type": "table"}, "force": True, "queries": [q],
            "form_data": form, "result_format": "json", "result_type": "full"}


def native_filter(key: str, name: str, dataset_id: int | None = None, column: str | None = None,
                  excluded: list[int] | None = None, default: str | None = None) -> dict:
    time = column is None
    mask = {"extraFormData": {}, "filterState": {}}
    if time:
        mask = {"extraFormData": {"time_range": "No filter"}, "filterState": {"value": "No filter"}}
    elif default is not None:
        mask = {"extraFormData": {"filters": [{"col": column, "op": "IN", "val": [default]}]},
                "filterState": {"value": [default], "label": default}}
    return {"id": "NATIVE_FILTER-" + key, "name": name, "filterType": "filter_time" if time else "filter_select",
            "type": "NATIVE_FILTER", "targets": [{}] if time else [{"datasetId": dataset_id, "column": {"name": column}}],
            "controlValues": {"multiSelect": default is None, "enableEmptyFilter": False, "searchAllOptions": True},
            "defaultDataMask": mask, "cascadeParentIds": [], "scope": {"rootPath": ["ROOT_ID"], "excluded": excluded or []}}


def position(definition: dict, chart_ids: dict[str, int]) -> dict:
    layout = {"DASHBOARD_VERSION_KEY": "v2", "ROOT_ID": {"id": "ROOT_ID", "type": "ROOT", "children": ["GRID_ID"]},
              "GRID_ID": {"id": "GRID_ID", "type": "GRID", "children": [], "parents": ["ROOT_ID"]},
              "HEADER_ID": {"id": "HEADER_ID", "type": "HEADER", "meta": {"text": definition["title"]}}}
    rows = [[("notice", 12, 26)]] + definition["rows"]
    for index, row in enumerate(rows):
        row_id = "ROW-" + str(index)
        layout["GRID_ID"]["children"].append(row_id)
        layout[row_id] = {"id": row_id, "type": "ROW", "children": [], "parents": ["ROOT_ID", "GRID_ID"], "meta": {"background": "BACKGROUND_TRANSPARENT"}}
        for key, width, height in row:
            component = "COMPONENT-" + key
            layout[row_id]["children"].append(component)
            meta = {"width": width, "height": height}
            if key == "notice":
                meta.update(code=definition["notice"])
                kind = "MARKDOWN"
            else:
                meta.update(chartId=chart_ids[key], uuid=uid("chart/" + key))
                kind = "CHART"
            layout[component] = {"id": component, "type": kind, "children": [], "parents": ["ROOT_ID", "GRID_ID", row_id], "meta": meta}
    return layout


def create(api: API) -> list[dict]:
    ids = prepare_datasets(api)
    chart_ids = {}
    for definition in charts():
        dataset_id = ids[definition["dataset"]]
        form = {"viz_type": definition["viz"], "datasource": f"{dataset_id}__table", "time_range": "No filter",
                "granularity_sqla": datasets()[definition["dataset"]]["main_dttm_col"], "adhoc_filters": [],
                "row_limit": 10000, "groupby": [], "color_scheme": "supersetColors", "show_legend": False,
                "legendOrientation": "bottom", "legendType": "scroll", "legendMargin": 20,
                "y_axis_format": ",.0f", "x_axis_time_format": "%H:%M", "time_format": "%Y-%m-%d %H:%M:%S",
                "show_markers": True, "markerSize": 5, "rich_tooltip": True, "truncate_metric": True,
                "truncate_cells": True, "table_timestamp_format": "%Y-%m-%d %H:%M:%S", **definition["form"]}
        context = query_context(dataset_id, form)
        payload = {"slice_name": definition["title"], "viz_type": definition["viz"], "datasource_id": dataset_id,
                   "datasource_type": "table", "params": json.dumps(form), "query_context": json.dumps(context),
                   "description": datasets()[definition["dataset"]]["description"]}
        chart_ids[definition["key"]] = api.upsert("chart", uid("chart/" + definition["key"]), payload)
    result = []
    for definition in DASHBOARDS:
        scoped = {key: value for key, value in chart_ids.items() if key.startswith(definition["prefix"])}
        data_key = "events" if definition["prefix"] == "traffic-" else "windows" if definition["prefix"] == "security-" else "captures"
        filters = [native_filter(definition["prefix"]+"capture", "Capture", ids[data_key], "capture_name"),
                   native_filter(definition["prefix"]+"source", "Source IP", ids[data_key], "source_ip")]
        if definition["prefix"] == "security-":
            filters.append(native_filter("alert-type", "Alert type (alert charts)", ids["alerts"], "alert_type", excluded=[chart_ids["security-nx-volume"],chart_ids["security-entropy-length"]]))
        if definition["prefix"] == "comparison-":
            filters.append(native_filter("detector", "Detector (comparison only)", ids["detectors"], "detector", excluded=[value for key,value in scoped.items() if key not in ("comparison-rates","comparison-counts")]))
        metadata = {"native_filter_configuration": filters,"color_scheme":"supersetColors",
                    "label_colors":{"CTU Normal":"#287ca8","CTU Malware":"#d49a29","MEDIUM":"#d49a29","HIGH":"#d84b67"},
                    "cross_filters_enabled":False}
        dashboard_id = api.upsert("dashboard", uid("dashboard/" + definition["slug"]), {
            "dashboard_title": definition["title"], "slug": definition["slug"], "published": True,
            "position_json": json.dumps(position(definition, chart_ids)), "json_metadata": json.dumps(metadata), "css": CSS})
        for key, chart_id in scoped.items():
            detail = api.call("GET", f"/api/v1/chart/{chart_id}")["result"]
            others = [item["id"] for item in detail.get("dashboards", []) if item["id"] != dashboard_id]
            api.call("PUT", f"/api/v1/chart/{chart_id}", json={"dashboards": others + [dashboard_id]})
        result.append({"id": dashboard_id, "slug": definition["slug"], "charts": len(scoped)})
        print(f"Dashboard {definition['slug']}: {len(scoped)} charts")
    return result


def verify(api: API) -> list[dict]:
    result = []
    for definition in DASHBOARDS:
        dashboard = api.call("GET", "/api/v1/dashboard/" + definition["slug"])["result"]
        attached = api.call("GET", f"/api/v1/dashboard/{dashboard['id']}/charts")["result"]
        expected = [item for item in charts() if item["key"].startswith(definition["prefix"])]
        if len(attached) != len(expected):
            raise RuntimeError("Unexpected chart count: " + definition["slug"])
        layout = json.loads(dashboard["position_json"])
        positioned = {item["meta"]["chartId"] for item in layout.values()
                      if isinstance(item, dict) and item.get("type") == "CHART"}
        if positioned != {item["id"] for item in attached}:
            raise RuntimeError("Dashboard layout differs from attached charts")
        for item in layout.values():
            if isinstance(item, dict) and item.get("type") == "ROW":
                assert sum(layout[child]["meta"]["width"] for child in item["children"]) == 12
        metadata = json.loads(dashboard["json_metadata"])
        assert len(metadata["native_filter_configuration"]) == (2 if definition["prefix"] == "traffic-" else 3)
        for chart in attached:
            data = api.call("GET", f"/api/v1/chart/{chart['id']}/data/", params={"force": "true"})
            for query in data["result"]:
                if query.get("error") or query.get("status") == "failed":
                    raise RuntimeError(f"Chart {chart['id']} failed: {query.get('error')}")
            print(f"Chart {chart['id']}: query OK")
        result.append({"slug": definition["slug"], "charts": len(attached)})
    return result


def export_assets(api: API, destination: Path, dashboards: list[dict] | None = None) -> None:
    ids = [api.call("GET", "/api/v1/dashboard/" + item["slug"])["result"]["id"] for item in (DASHBOARDS if dashboards is None else dashboards)]
    response = api.session.get(api.base + "/api/v1/dashboard/export/", params={"q": json.dumps(ids)}, timeout=120)
    response.raise_for_status()
    source = zipfile.ZipFile(io.BytesIO(response.content))
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    for name in source.namelist():
        if not name.endswith((".yaml", ".yml")):
            continue
        relative = Path(*Path(name).parts[1:])
        if ".." in relative.parts or relative.is_absolute():
            raise RuntimeError("Unsafe asset path")
        doc = yaml.safe_load(source.read(name))
        if relative.parts[0] == "databases":
            doc = {k: doc[k] for k in ("database_name", "uuid", "version") if k in doc}
            doc.update(sqlalchemy_uri="postgresql+psycopg2://READER:XXXXXXXXXX@postgres:5432/ANALYTICS_DB",
                       expose_in_sqllab=True, allow_ctas=False, allow_cvas=False, allow_dml=False, allow_run_async=False,
                       extra={"engine_params": {"connect_args": {"options": "-c timezone=UTC"}}})
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(doc, sort_keys=False))
        count += 1
    print(f"Exported {count} sanitized YAML assets to {destination}")


def import_assets(api: API, directory: Path) -> dict:
    database = next(item for item in api.listing("database") if item["database_name"] == "DNS Security Analytics (read-only)")
    buffer = io.BytesIO()
    passwords = {}
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob("*.yaml")):
            relative = path.relative_to(directory)
            doc = yaml.safe_load(path.read_text())
            if relative.parts[0] == "databases":
                doc["uuid"] = database["uuid"]
                user, name = quote(os.environ["SUPERSET_ANALYTICS_USER"], safe=""), quote(os.environ["SUPERSET_ANALYTICS_DB"], safe="")
                doc["sqlalchemy_uri"] = f"postgresql+psycopg2://{user}:XXXXXXXXXX@postgres:5432/{name}"
                passwords[str(relative)] = os.environ["SUPERSET_ANALYTICS_PASSWORD"]
            elif relative.parts[0] == "datasets":
                doc["database_uuid"] = database["uuid"]
            archive.writestr("dns_assets/" + str(relative), yaml.safe_dump(doc, sort_keys=False))
    result = api.call("POST", "/api/v1/dashboard/import/", files={"formData": ("dashboards.zip", buffer.getvalue(), "application/zip")},
                      data={"overwrite": "true", "passwords": json.dumps(passwords)})
    print("Sanitized dashboard asset import succeeded.")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify", "export", "import"))
    parser.add_argument("--url", default="http://superset:8088")
    parser.add_argument("--assets", type=Path, default=Path("/assets"))
    args = parser.parse_args()
    api = API(args.url)
    if args.action == "create":
        create(api)
    elif args.action == "verify":
        verify(api)
    elif args.action == "export":
        export_assets(api, args.assets)
    else:
        import_assets(api, args.assets)


if __name__ == "__main__":
    main()
