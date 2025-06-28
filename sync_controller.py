import os
import json
import logging
from kubernetes import client, config, watch
from pymongo import MongoClient

CONFIG_PATH = os.environ.get("CONFIG_PATH", "./config.local.json")
with open(CONFIG_PATH) as f:
    cfg = json.load(f)

MONGO_URI = cfg["mongo_uri"]
MONGO_DB = cfg["mongo_db"]


def get_cluster_name(logger):
    try:
        v1 = client.CoreV1Api()
        nodes = v1.list_node()
        for node in nodes.items:
            for key in [
                "cluster-name",
                "kubernetes.azure.com/cluster",
                "eks.amazonaws.com/cluster-name",
            ]:
                if key in node.metadata.labels:
                    logger.info(
                        f"Detected cluster name from node label: {node.metadata.labels[key]}"
                    )
                    return node.metadata.labels[key]
    except Exception as e:
        logger.debug(f"Could not get cluster name from node labels: {e}")

    try:
        _, active_context = config.list_kube_config_contexts()
        if (
            active_context
            and "context" in active_context
            and "cluster" in active_context["context"]
        ):
            logger.info(
                f"Detected cluster name from kubeconfig: {active_context['context']['cluster']}"
            )
            return active_context["context"]["cluster"]
    except Exception as e:
        logger.debug(f"Could not get cluster name from kubeconfig: {e}")

    logger.info(
        f"Using cluster name from config: {cfg.get('cluster', 'unknown-cluster')}"
    )
    return cfg.get("cluster", "unknown-cluster")


LOG_LEVEL = cfg.get("log_level", "info").upper()
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("sync-controller")
CLUSTER = get_cluster_name(logger)

mongo_client = MongoClient(MONGO_URI)
db = mongo_client[MONGO_DB]


def load_kube_config():
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster kube config")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kube config")


load_kube_config()

aqua_resources = [
    "vulnerabilityreports",
    "clustercompliancereports",
    "clusterconfigauditreports",
    "clusterinfraassessmentreports",
    "clusterrbacassessmentreports",
    "clustersbomreports",
    "clustervulnerabilityreports",
    "configauditreports",
    "exposedsecretreports",
    "infraassessmentreports",
    "rbacassessmentreports",
    "sbomreports",
]


def sync_to_mongo(resource_type, obj, event_type):
    meta = obj.get("metadata", {})
    doc = {
        "_event_type": event_type,
        "_resource_type": resource_type,
        "_namespace": meta.get("namespace"),
        "_name": meta.get("name"),
        "_cluster": CLUSTER,
        "data": obj,
    }
    uid = meta.get("uid")
    if not uid:
        logger.warning(f"No UID for {resource_type} {meta.get('name')}")
        return
    db[resource_type].replace_one({"_uid": uid}, {"_uid": uid, **doc}, upsert=True)
    logger.info(f"Synced {resource_type} {meta.get('name')} ({event_type})")


def initial_import_resource(resource_type):
    group = "aquasecurity.github.io"
    version = "v1alpha1"
    plural = resource_type
    api = client.CustomObjectsApi()
    try:
        objs = api.list_cluster_custom_object(group, version, plural)
        items = objs.get("items", [])
        logger.info(f"Initial import: {len(items)} {resource_type}")
        current_uids = set()
        for obj in items:
            uid = obj.get("metadata", {}).get("uid")
            if uid:
                current_uids.add(uid)
            sync_to_mongo(resource_type, obj, "INITIAL_IMPORT")
        result = db[resource_type].delete_many({"_uid": {"$nin": list(current_uids)}})
        logger.info(
            f"Removed {result.deleted_count} stale records from {resource_type}"
        )
    except Exception as e:
        logger.error(f"Error during initial import of {resource_type}: {e}")


def watch_resource(resource_type):
    group = "aquasecurity.github.io"
    version = "v1alpha1"
    plural = resource_type
    api = client.CustomObjectsApi()
    w = watch.Watch()
    while True:
        try:
            for event in w.stream(
                api.list_cluster_custom_object,
                group,
                version,
                plural,
                timeout_seconds=60,
            ):
                obj = event["object"]
                event_type = event["type"]
                sync_to_mongo(resource_type, obj, event_type)
        except Exception as e:
            logger.error(f"Error watching {resource_type}: {e}")


def sync_namespace_to_mongo(obj, event_type):
    meta = obj.get("metadata", {})
    doc = {
        "_event_type": event_type,
        "_resource_type": "namespace",
        "_name": meta.get("name"),
        "_cluster": CLUSTER,
        "data": obj,
    }
    uid = meta.get("uid")
    if not uid:
        logger.warning(f"No UID for namespace {meta.get('name')}")
        return
    db["namespaces"].replace_one({"_uid": uid}, {"_uid": uid, **doc}, upsert=True)
    logger.info(f"Synced namespace {meta.get('name')} ({event_type})")


def initial_import_namespaces():
    v1 = client.CoreV1Api()
    try:
        ns_list = v1.list_namespace()
        logger.info(f"Initial import: {len(ns_list.items)} namespaces")
        current_uids = set()
        for ns in ns_list.items:
            ns_dict = ns.to_dict()
            uid = ns_dict.get("metadata", {}).get("uid")
            if uid:
                current_uids.add(uid)
            sync_namespace_to_mongo(ns_dict, "INITIAL_IMPORT")
        result = db["namespaces"].delete_many({"_uid": {"$nin": list(current_uids)}})
        logger.info(f"Removed {result.deleted_count} stale records from namespaces")
    except Exception as e:
        logger.error(f"Error during initial import of namespaces: {e}")


def watch_namespaces():
    v1 = client.CoreV1Api()
    w = watch.Watch()
    while True:
        try:
            for event in w.stream(v1.list_namespace, timeout_seconds=60):
                obj = event["object"].to_dict()
                event_type = event["type"]
                sync_namespace_to_mongo(obj, event_type)
        except Exception as e:
            logger.error(f"Error watching namespaces: {e}")


if __name__ == "__main__":
    import threading

    for res in aqua_resources:
        initial_import_resource(res)
    initial_import_namespaces()

    threads = []
    for res in aqua_resources:
        t = threading.Thread(target=watch_resource, args=(res,), daemon=True)
        t.start()
        threads.append(t)
    t_ns = threading.Thread(target=watch_namespaces, daemon=True)
    t_ns.start()
    threads.append(t_ns)
    logger.info("Controller started. Watching resources and namespaces...")
    for t in threads:
        t.join()
