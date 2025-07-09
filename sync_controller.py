import os
import json
import logging
from kubernetes import client, config, watch
from pymongo import MongoClient
from falco_client import FalcoAlertConsumer

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

# Aqua Security resources
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

# Falco resources
falco_resources = [
    "falcos",
    "falcorules",
    "falcorulegroupses",
]

# Resource groups configuration
resource_groups = {
    "aquasecurity.github.io": {
        "version": "v1alpha1",
        "resources": aqua_resources,
    },
    "falco.security.io": {
        "version": "v1alpha1",
        "resources": falco_resources,
    },
}


def sync_to_mongo(api_group, resource_type, obj, event_type):
    meta = obj.get("metadata", {})
    doc = {
        "_event_type": event_type,
        "_api_group": api_group,
        "_resource_type": resource_type,
        "_namespace": meta.get("namespace"),
        "_name": meta.get("name"),
        "_cluster": CLUSTER,
        "data": obj,
    }
    uid = meta.get("uid")
    if not uid:
        logger.warning(f"No UID for {api_group}/{resource_type} {meta.get('name')}")
        return

    # Use api_group + resource_type as collection name to avoid conflicts
    collection_name = f"{api_group.replace('.', '_')}_{resource_type}"
    db[collection_name].replace_one({"_uid": uid}, {"_uid": uid, **doc}, upsert=True)
    logger.info(f"Synced {api_group}/{resource_type} {meta.get('name')} ({event_type})")


def check_crd_exists(api_group, resource_type):
    """Check if a CRD exists in the cluster"""
    try:
        api = client.ApiextensionsV1Api()
        crd_name = f"{resource_type}.{api_group}"
        api.read_custom_resource_definition(crd_name)
        return True
    except Exception:
        return False


def initial_import_resource(api_group, version, resource_type):
    if not check_crd_exists(api_group, resource_type):
        logger.warning(f"CRD {resource_type}.{api_group} not found, skipping")
        return

    api = client.CustomObjectsApi()
    try:
        objs = api.list_cluster_custom_object(api_group, version, resource_type)
        items = objs.get("items", [])
        logger.info(f"Initial import: {len(items)} {api_group}/{resource_type}")
        current_uids = set()
        for obj in items:
            uid = obj.get("metadata", {}).get("uid")
            if uid:
                current_uids.add(uid)
            sync_to_mongo(api_group, resource_type, obj, "INITIAL_IMPORT")

        collection_name = f"{api_group.replace('.', '_')}_{resource_type}"
        result = db[collection_name].delete_many({"_uid": {"$nin": list(current_uids)}})
        logger.info(
            f"Removed {result.deleted_count} stale records from {api_group}/{resource_type}"
        )
    except Exception as e:
        logger.error(f"Error during initial import of {api_group}/{resource_type}: {e}")


def watch_resource(api_group, version, resource_type):
    if not check_crd_exists(api_group, resource_type):
        logger.warning(f"CRD {resource_type}.{api_group} not found, skipping watcher")
        return

    api = client.CustomObjectsApi()
    w = watch.Watch()
    while True:
        try:
            for event in w.stream(
                api.list_cluster_custom_object,
                api_group,
                version,
                resource_type,
                timeout_seconds=60,
            ):
                obj = event["object"]
                event_type = event["type"]
                sync_to_mongo(api_group, resource_type, obj, event_type)
        except Exception as e:
            logger.error(f"Error watching {api_group}/{resource_type}: {e}")
            if "404" in str(e):
                logger.warning(
                    f"CRD {resource_type}.{api_group} was removed, stopping watcher"
                )
                break
            # Wait before retrying on other errors
            import time

            time.sleep(30)


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

    # Check which CRDs are available before starting
    logger.info("Checking available CRDs...")
    available_groups = {}
    # for api_group, config_data in resource_groups.items():
    #     available_resources = []
    #     for resource_type in config_data["resources"]:
    #         if check_crd_exists(api_group, resource_type):
    #             available_resources.append(resource_type)
    #             logger.info(f"✅ Found CRD: {resource_type}.{api_group}")
    #         else:
    #             logger.warning(f"❌ Missing CRD: {resource_type}.{api_group}")

    #     if available_resources:
    #         available_groups[api_group] = {
    #             "version": config_data["version"],
    #             "resources": available_resources,
    #         }
    #     else:
    #         logger.warning(f"No CRDs found for API group: {api_group}")

    # Initial import for available resource groups only
    for api_group, config_data in available_groups.items():
        version = config_data["version"]
        for resource_type in config_data["resources"]:
            initial_import_resource(api_group, version, resource_type)

    initial_import_namespaces()

    threads = []

    # Start watchers for available resource groups only
    # for api_group, config_data in available_groups.items():
    #     version = config_data["version"]
    #     for resource_type in config_data["resources"]:
    #         t = threading.Thread(
    #             target=watch_resource,
    #             args=(api_group, version, resource_type),
    #             daemon=True,
    #         )
    #         t.start()
    #         threads.append(t)

    # Start namespace watcher
    t_ns = threading.Thread(target=watch_namespaces, daemon=True)
    t_ns.start()
    threads.append(t_ns)

    # Start Falco alert consumer if enabled
    falco_config = cfg.get("falco", {})
    if falco_config.get("enabled", False):
        logger.info("Starting Falco alert consumer...")
        falco_consumer = FalcoAlertConsumer(
            mongo_db=db,
            cluster_name=CLUSTER,
            logger=logger,
            namespace=falco_config.get("namespace", "falco-system"),
        )
        falco_consumer.start()
    else:
        logger.info("Falco integration disabled in configuration")

    if available_groups:
        available_apis = ", ".join(available_groups.keys())
        logger.info(
            f"Controller started. Watching {available_apis} resources and namespaces..."
        )
    else:
        logger.info(
            "Controller started. Only watching namespaces (no custom resource CRDs found)..."
        )

    for t in threads:
        t.join()
