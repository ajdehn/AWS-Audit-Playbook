import os
from botocore.exceptions import ClientError
from utils import save_json, load_json_if_exists


class EvidenceClient:
    def __init__(self, evidence_folder_path, debug=False):
        self.base_path = evidence_folder_path       # Path to audit evidence folder.
        self.debug = debug                          # Print cache behavior

    def get(self, relative_path, fetch_fn):
        file_path = os.path.join(self.base_path, relative_path)

        if os.path.exists(file_path):
            if self.debug:
                print(f"[CACHE HIT] {file_path}")
            return load_json_if_exists(file_path)

        if self.debug:
            print(f"[FETCHING] {file_path}")

        data = fetch_fn()
        save_json(data, file_path.lower())
        return data

    """
        AWS-safe fetch wrapper with optional pagination support.
        Returns flattened ResponseMetadata (from last page).

        paginator_params: dict with keys:
        - method_name: str (e.g., 'list_users')
        - pagination_key: str (key in each page to combine, e.g., 'Users')
        - params: dict (parameters to pass to the AWS method)
    """
    def get_aws(self, relative_path, fetch_fn, not_found_codes=None, paginator_params=None):
        def wrapped():
            try:
                if paginator_params:
                    client = paginator_params.get("client") # boto3 client
                    method_name = paginator_params["method_name"]
                    pagination_key = paginator_params["pagination_key"]
                    params = paginator_params.get("params", {})

                    paginator = client.get_paginator(method_name)
                    items = []
                    last_metadata = {}

                    for page in paginator.paginate(**params):
                        # Collect items
                        items.extend(page.get(pagination_key, []))

                        # Keep overwriting → ends up with last page metadata
                        last_metadata = page.get("ResponseMetadata", {})

                    return {
                        pagination_key: items,
                        "ResponseMetadata":  last_metadata
                    }

                # Non-paginated call
                response = fetch_fn()
                return response

            except ClientError as e:
                code = e.response["Error"]["Code"]
                if not_found_codes and code in not_found_codes:
                    return None
                raise

        return self.get(relative_path, wrapped)