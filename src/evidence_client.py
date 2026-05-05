import os
from utils import save_json, load_json
import botocore

class EvidenceClient:
    def __init__(self, evidence_folder_path, session=None, debug=False, cache_only=False):
        """
        evidence_folder_path: root folder for storing audit evidence
        debug: print cache behavior
        cache_only: only use cached evidence, do not make API calls to retrieve evidence
        """
        
        self.base_path = evidence_folder_path
        self.debug = debug
        self.cache_only = cache_only
        # TODO: Build session into the constructor
        self.session = session

    def _log(self, message: str):
        if self.debug:
            print(message)

    def _get_client(self, service: str, region: str | None = None):
        if self.cache_only:
            raise RuntimeError("AWS client access attempted in cache_only mode")
        
        if not self.session:
            raise ValueError("EvidenceClient.session is not initialized")

        return self.session.client(service, region_name=region)

    def get(self, relative_path, fetch_fn=None, optional=False):
        """
        Fetches cached JSON data from a relative path, if available.
        If not available in cache, calls fetch_fn() to retrieve the data.

        relative_path: file path describing where evidence should be saved (e.g., s3/buckets.json)
        fetch_fn: function called when data is not cached (e.g. lambda: s3.list_buckets())
        optional: if True, returns None instead of raising an error if cached evidence is not available.
        """

        file_path = os.path.join(self.base_path, relative_path)
        
        # Option 1: Search for cached evidence.
        if os.path.exists(file_path):
            self._log(f"[CACHE HIT] {file_path}")
            return load_json(file_path)

        # Option 2: Check cache_only mode (no fetching allowed).
        if self.cache_only:
            if optional:
                self._log(f"[CACHE_ONLY] Optional evidence not found: {file_path} → returning None")
                return None
            raise FileNotFoundError(f"[CACHE_ONLY] Missing required file: {file_path}")

        # Option 3: Cached evidence not available, fetch_fn not provided.
        if fetch_fn is None:
            raise ValueError("fetch_fn must be provided when not using cache")

        # Option 4: Fetch and cache for future use.
        data = fetch_fn()
        save_json(data, file_path)
        return data

    def _paginate(self, client, method_name, pagination_key, params=None):
        params = params or {}

        paginator = client.get_paginator(method_name)
        items = []
        last_metadata = {}

        for page in paginator.paginate(**params):
            items.extend(page.get(pagination_key, []))
            last_metadata = page.get("ResponseMetadata", {})

        return {
            pagination_key: items,
            "ResponseMetadata": last_metadata
        }

    def get_aws(self, relative_path, client=None, service=None, region=None, method=None, method_kwargs=None, not_found_codes=None, paginator_params=None):
        """
            AWS-safe fetch wrapper with optional pagination support.
            Returns requested evidence.
            NOTE: When paginating evidence, the ResponseMetadata is flattened (from the last page).

            relative_path: file path describing where evidence should be saved (e.g., s3/buckets.json)
            client: AWS client. If client is set, service is not required.
            service: AWS service name (e.g., 's3')
            method: AWS method name (e.g., 'list_buckets', 'get_bucket_encryption')
            method_kwargs: dict (arguments to pass to the AWS method). E.g. {"Bucket": "my-bucket"}
            not_found_codes: list of potential AWS error codes (e.g., ["ServerSideEncryptionConfigurationNotFoundError"]).
            NOTE: not_found_codes is used to avoid errors when 'optional' evidence is not available.
            paginator_params: dict with keys:
            - method_name: str (e.g., 'list_users')
            - pagination_key: str (key in each page to combine, e.g., 'Users')
            - params: dict (parameters to pass to the AWS method)
        """

        def _build_fetch_fn():
            # NOTE: This builds the fetch function, but it only executes if the cached evidence is not found.

            if self.cache_only:
                raise RuntimeError("Attempted AWS fetch in cache_only mode")

            try:
                resolved_client = client

                if resolved_client is None:
                    if service is None:
                        raise ValueError("Service is required when client is not provided")
                    resolved_client = self._get_client(service, region=region)

                # Option 1: Handle pagination
                if paginator_params:
                    # Check if all required pagination keys are included
                    required_pagination_keys = ["method_name", "pagination_key"]
                    missing_keys = [key for key in required_pagination_keys if key not in paginator_params]
                    if missing_keys:
                        raise ValueError(
                            f"Missing required paginator_params keys: {missing_keys}. "
                            f"Required keys are: {required_pagination_keys}"
                        )

                    return self._paginate(
                        client=resolved_client,
                        method_name=paginator_params["method_name"],
                        pagination_key=paginator_params["pagination_key"],
                        params=paginator_params.get("params")
                    )

                # Option 2: Direct method call
                if method:
                    fn = getattr(resolved_client, method)
                    return fn(**(method_kwargs or {}))

                raise ValueError("Must provide either paginator_params or method")

            except botocore.exceptions.ClientError as e:
                code = e.response.get("Error", {}).get("Code")

                if not_found_codes and code in not_found_codes:
                    self._log(f"[AWS NOT FOUND] {code} for {relative_path} → returning None")
                    return None

                raise


        optional_file = False
        # File is optional if not_found_codes are provided
        if not_found_codes:
            optional_file = True
        return self.get(relative_path, fetch_fn=_build_fetch_fn, optional=optional_file)