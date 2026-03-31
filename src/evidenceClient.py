import os
import botocore
from utils import save_json, load_json_if_exists

class EvidenceClient:
    def __init__(self, base_path, debug=False):
        """
        base_path: root folder for evidence (e.g., audit.evidence_folder)
        debug: print cache behavior
        """
        self.base_path = base_path
        self.debug = debug

    # ---------------------------
    # Public API
    # ---------------------------
    def get(self, relative_path, fetch_fn):
        """
        Fetch data with simple caching (no expiration).
        """
        file_path = os.path.join(self.base_path, relative_path)

        if os.path.exists(file_path):
            if self.debug:
                print(f"[CACHE HIT] {file_path}")
            return load_json_if_exists(file_path)

        if self.debug:
            print(f"[FETCHING] {file_path}")

        data = fetch_fn()
        save_json(data, file_path)
        return data

    def get_aws(self, relative_path, fetch_fn, not_found_codes=None, paginator_params=None):
        """
        AWS-safe fetch wrapper with optional pagination support.
        
        paginator_params: dict with keys:
            - method_name: str (e.g., 'list_users')
            - pagination_key: str (key in each page to combine, e.g., 'Users')
            - params: dict (parameters to pass to the AWS method)
        """
        def wrapped():
            try:
                if paginator_params:
                    client = paginator_params.get("client")  # boto3 client
                    method_name = paginator_params["method_name"]
                    pagination_key = paginator_params["pagination_key"]
                    params = paginator_params.get("params", {})

                    # Use boto3 paginator
                    paginator = client.get_paginator(method_name)
                    items = []
                    for page in paginator.paginate(**params):
                        items.extend(page.get(pagination_key, []))
                    return {pagination_key: items}

                return fetch_fn()
            except botocore.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                if not_found_codes and code in not_found_codes:
                    return None
                raise

        return self.get(relative_path, wrapped)