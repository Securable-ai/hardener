"""
Intercept.py

This script is used to intercept the traffic and log the
requests to a file. It also blocks the requests based on
the rules defined in the egress_rules.yaml file.
"""

import json
import logging
import os
import re
import time
from queue import Queue
from threading import Lock, Thread

# pylint: disable=import-error
import ruamel.yaml
from mitmproxy import ctx
from OpenSSL import SSL

FILE_WORKERS = 5

DEFAULT_EGRESS_RULES_YAML = """
- name: 'Reqd by Github Action'
  description: 'Needed for essential operations'
  destination: 'github.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for essential operations'
  destination: 'api.github.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for essential operations'
  destination: '*.actions.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for downloading actions'
  destination: 'codeload.github.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for uploading/downloading job \
summaries, logs, workflow artifacts, and caches'
  destination: 'results-receiver.actions.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for uploading/downloading job \
summaries, logs, workflow artifacts, and caches'
  destination: '*.blob.core.windows.net'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for runner version updates'
  destination: 'objects.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for runner version updates'
  destination: 'objects-origin.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for runner version updates'
  destination: 'github-releases.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for runner version updates'
  destination: 'github-registry-files.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for retrieving OIDC tokens'
  destination: '*.actions.githubusercontent.com'
  action: 'allow'
- name : 'Reqd by Github Action'
  description: 'Needed for downloading or publishing \
packages or containers to GitHub Packages'
  destination: '*.pkg.github.com'
  action: 'allow'
- name : 'Reqd by Github Action'
  description: 'Needed for downloading or publishing \
packages or containers to GitHub Packages'
  destination: 'ghcr.io'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for Git Large File Storage'
  destination: 'github-cloud.githubusercontent.com'
  action: 'allow'
- name: 'Reqd by Github Action'
  description: 'Needed for Git Large File Storage'
  destination: 'github-cloud.s3.amazonaws.com'
  action: 'allow'
- name: 'Reqd by NPM install'
  description: 'Needed for NPM install'
  destination: 'registry.npmjs.org'
  action: 'allow'
- name: 'Reqd for instance metadata'
  description: 'Needed for instance metadata'
  destination: '169.254.169.254'
  action: 'allow'
- name: 'Reqd for ECS metadata'
  description: 'Needed for ECS metadata'
  destination: '169.254.170.2'
  action: 'allow'
- name: 'Reqd for Analysis'
  description: 'Needed for sending results to securable API endpoint'
  destination: '*.securable.ai'
  action: 'allow'
"""


# pylint: disable=missing-function-docstring,unspecified-encoding
class Interceptor:
    """
    The Interceptor class is responsible for managing
    and controlling the flow of http requests.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.outfile = None
        self.encode = None
        self.url = None
        self.lock = None
        self.auth = None
        self.queue = Queue()
        self.egress_rules = None
        self.mode = os.environ.get("hardener_MODE", "audit")
        self.default_policy = os.environ.get("hardener_DEFAULT_POLICY", "block-all")
        trusted_github_accounts_string = os.environ.get(
            "hardener_TRUSTED_GITHUB_ACCOUNTS", ""
        )
        self.trusted_github_accounts = trusted_github_accounts_string.split(",")
        self.allow_http = os.environ.get("hardener_ALLOW_HTTP", False)
        with open("/home/hardener/egress_rules.yaml", "r") as file:
            yaml = ruamel.yaml.YAML(typ="safe", pure=True)
            self.egress_rules = yaml.load(file)
            default_egress_rules = yaml.load(DEFAULT_EGRESS_RULES_YAML)
            for rule in default_egress_rules:
                rule["default"] = True
            self.egress_rules = self.egress_rules + default_egress_rules

    def done(self):
        self.queue.join()
        if self.outfile:
            self.outfile.close()

    @classmethod
    def convert_to_strings(cls, obj):
        if isinstance(obj, dict):
            return {
                cls.convert_to_strings(key): cls.convert_to_strings(value)
                for key, value in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return [cls.convert_to_strings(element) for element in obj]
        if isinstance(obj, bytes):
            return str(obj)[2:-1]
        return obj

    def worker(self):
        while True:
            frame = self.queue.get()
            self.dump(frame)
            self.queue.task_done()

    def dump(self, frame):
        frame["mode"] = self.mode
        frame["timestamp"] = time.strftime("%X %x %Z")
        frame = self.convert_to_strings(frame)

        if self.outfile:
            # pylint: disable=consider-using-with
            self.lock.acquire()
            self.outfile.write(json.dumps(frame) + "\n")
            self.outfile.flush()
            self.lock.release()

    @staticmethod
    def load(loader):
        loader.add_option(
            "dump_destination",
            str,
            "jsondump.out",
            "Output destination: path to a file or URL.",
        )

    def configure(self, _):
        dump_destination = ctx.options.dump_destination
        # pylint: disable=consider-using-with
        self.outfile = open(dump_destination, "a")
        self.lock = Lock()
        logging.info("Writing all data frames to %s", dump_destination)

        for _ in range(FILE_WORKERS):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()

    def wildcard_to_regex(self, wildcard_destination):
        # Escape special characters
        regex_pattern = re.escape(wildcard_destination)
        # Replace wildcard with regex equivalent
        regex_pattern = regex_pattern.replace(r"\*", ".*")
        # Ensure the pattern matches the entire string
        regex_pattern = "^" + regex_pattern + "$"
        return re.compile(regex_pattern)

    # pylint: disable=too-many-branches
    def tls_clienthello(self, data):
        default_policy = self.default_policy
        destination = data.client_hello.sni

        matched_rules = []

        for rule in self.egress_rules:
            destination_pattern = self.wildcard_to_regex(rule["destination"])
            if destination_pattern.match(destination) is not None:
                matched_rules.append(rule)

        data.context.matched_rules = matched_rules

        # Disabling path based rules for now as it requires SSL inspection
        # has_paths = len(matched_rules) > 0 and "paths" in matched_rules[0]

        # if has_paths:
        #     return

        # Disabling SSL inspection for github.com and api.github.com
        # if destination in ["github.com", "api.github.com"]:
        # return

        applied_rule = matched_rules[0] if len(matched_rules) > 0 else None
        if applied_rule is not None:
            default_rules_applied = applied_rule.get("default", False)
        else:
            default_rules_applied = False

        if applied_rule is not None:
            applied_rule_name = applied_rule.get("name", "Name not configured")
        else:
            applied_rule_name = f"Default Policy - {default_policy}"

        if applied_rule is not None:
            block = applied_rule["action"] == "block"
        else:
            block = default_policy == "block-all"

        if block:
            event = {
                "action": "block",
                "destination": destination,
                "scheme": "https",
                "rule_name": applied_rule_name,
                "default": default_rules_applied,
            }
            data.context.action = "block"
            if self.mode == "audit":
                data.ignore_connection = True
        else:
            event = {
                "action": "allow",
                "destination": destination,
                "scheme": "https",
                "rule_name": applied_rule_name,
            }
            data.ignore_connection = True
            data.context.action = "allow"

        self.queue.put(event)

    def tls_start_client(self, data):
        logging.info("tls_start_client")
        action = data.context.action
        if action == "block" and self.mode != "audit":
            data.ssl_conn = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD))
            data.conn.error = "TLS Handshake failed"

    # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    def request(self, flow):
        allow_http = self.allow_http
        default_policy = self.default_policy

        sni = flow.client_conn.sni
        # pylint: disable=fixme
        # TODO: check whether host header is spoofed or not
        host = flow.request.pretty_host
        destination = sni if sni is not None else host
        scheme = flow.request.scheme
        request_path = flow.request.path
        request_method = flow.request.method

        if (not allow_http) and scheme == "http":
            event = {
                "action": "block",
                "destination": destination,
                "scheme": "http",
                "rule_name": "allow_http is False",
            }
            self.queue.put(event)
            if self.mode != "audit":
                flow.kill()
            return

        block = default_policy == "block-all"
        break_flag = False
        applied_rule = None

        for rule in self.egress_rules:
            destination_pattern = self.wildcard_to_regex(rule["destination"])
            if destination_pattern.match(destination) is not None:
                paths = rule.get("paths", [])
                # Disable path based rules for now.
                paths = []
                if len(paths) == 0:
                    block = rule["action"] == "block"
                    applied_rule = rule
                    break
                for path in paths:
                    path_regex = self.wildcard_to_regex(path)
                    if path_regex.match(request_path) is not None:
                        block = rule["action"] == "block"
                        applied_rule = rule
                        break_flag = True
                        break
                if break_flag:
                    break

        if applied_rule is not None:
            applied_rule_name = applied_rule.get("name", "Name not configured")
        else:
            applied_rule_name = f"Default Policy - {default_policy}"

        normalised_request_path = request_path
        if not normalised_request_path.endswith("/"):
            normalised_request_path = normalised_request_path + "/"

        if not normalised_request_path.startswith("/"):
            normalised_request_path = "/" + normalised_request_path

        trusted_github_account_flag = None
        if destination == "api.github.com":
            if normalised_request_path.startswith(
                "/orgs/"
            ) or normalised_request_path.startswith("/repos/"):
                for trusted_github_account in self.trusted_github_accounts:
                    if normalised_request_path.startswith(
                        f"/orgs/{trusted_github_account}/"
                    ) or normalised_request_path.startswith(
                        f"/repos/{trusted_github_account}/"
                    ):
                        trusted_github_account_flag = True
                        break
                if trusted_github_account_flag is None:
                    trusted_github_account_flag = False

        if destination == "github.com":
            for trusted_github_account in self.trusted_github_accounts:
                if normalised_request_path.startswith(f"/{trusted_github_account}/"):
                    trusted_github_account_flag = True
                    break
            if trusted_github_account_flag is None:
                trusted_github_account_flag = False

        if applied_rule is not None:
            default_rules_applied = applied_rule.get("default", False)
        else:
            default_rules_applied = False

        if block:
            event = {
                "action": "block",
                "destination": destination,
                "scheme": scheme,
                "rule_name": applied_rule_name,
                "default": default_rules_applied,
            }
            if self.mode != "audit":
                flow.kill()
        else:
            event = {
                "action": "allow",
                "destination": destination,
                "scheme": scheme,
                "rule_name": applied_rule_name,
                "default": default_rules_applied,
            }

        if trusted_github_account_flag is not None:
            github_account_name = request_path.split("/")[2]
            event["trusted_github_account_flag"] = trusted_github_account_flag
            event["github_account_name"] = github_account_name
            event["request_path"] = request_path
            event["request_method"] = request_method

        self.queue.put(event)


addons = [Interceptor()]  # pylint: disable=invalid-name
