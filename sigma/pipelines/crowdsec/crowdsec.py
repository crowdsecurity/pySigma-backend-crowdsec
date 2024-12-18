"""Crowdsec backend for Sigma rules."""
# pylint: disable=line-too-long

from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.base import Pipeline

@Pipeline
def crowdsec_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    """Crowdsec processing pipeline for Sigma rules."""
    return ProcessingPipeline(
        name="crowdsec pipeline",
        allowed_backends={"crowdsec"},                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_webserver_fieldmapping",
                rule_conditions=[LogsourceCondition(category="webserver",)],
                transformation=FieldMappingTransformation({
                    "date": "evt.StrTime",
                    "time": "evt.StrTime",
                    "c-ip": "evt.Meta.source_ip",
                    "cs-username": "evt.Parsed.remote_user",
                    "s-sitename": "evt.Parsed.target_fqdn",
                    "cs-method": "evt.Meta.http_verb",
                    "cs-uri-stem": "evt.Meta.http_path",
                    "cs-uri-query": "evt.Parsed.http_args",
                    "sc-status": "int(evt.Meta.http_status)",
                    "c-win23-status": "int(evt.Meta.http_status)", #same as sc-status
                    "sc-bytes": "int(evt.Parsed.body_bytes_sent)",
                    "cs-bytes": "int(evt.Parsed.request_length)",
                    "time-taken": "evt.Parsed.request_time", #no part of default logging formats
                    "cs-version": "evt.Parsed.http_version",
                    "cs-host": "evt.Parsed.target_fqdn",
                    "cs-user-agent": "evt.Meta.http_user_agent",
                    "cs-referer": "evt.Parsed.http_referer",
#                   "cs-cookie": "N/A", (TBD) no part of default logging formats
#                   "s-computername": "N/A", (TBD) might only be present from web logs over syslog?
#                   "s-ip": "N/A", (TBD) might only be present from web logs over syslog?
#                   "s-port": "N/A", (TBD) might only be present from web logs over syslog?
                })
            ),
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_windows_process_creation_fieldmapping",
                rule_conditions=[LogsourceCondition(category="process_creation",product="windows",)],
                transformation=FieldMappingTransformation({
                    #"EventID": "int(evt.Parsed.EventID)",
                    "Computer" : "evt.Parsed.Computer",                   
                    "Company": "evt.Parsed.Company",
                    "OriginalFileName" : "evt.Parsed.OriginalFileName",
                    "UtcTime": "evt.StrTime",
                    "ProcessGuid": "evt.Parsed.ProcessGuid",
                    "ProcessId": "int(evt.Parsed.ProcessId)",
                    "Image": "evt.Parsed.Image",
                    "FileVersion": "evt.Parsed.FileVersion",
                    "Description": "evt.Parsed.Description",
                    "CommandLine": "evt.Parsed.CommandLine",
                    "CurrentDirectory": "evt.Parsed.CurrentDirectory",
                    "User": "evt.Parsed.User",
                    "LogonGuid": "evt.Parsed.LogonGuid",
                    "LogonId": "int(evt.Parsed.LogonId)",
                    "TerminalSessionId": "evt.Parsed.TerminalSessionId",
                    "IntegrityLevel": "evt.Parsed.IntegrityLevel",
                    "ParentProcessGuid": "evt.Parsed.ParentProcessGuid",
                    "ParentProcessId": "int(evt.Parsed.ParentProcessId)",
                    "ParentImage": "evt.Parsed.ParentImage",
                    "ParentCommandLine": "evt.Parsed.ParentCommandLine",
                    "Product": "evt.Parsed.Product",
                    "Hashes": "evt.Parsed.Hashes",
                    "ParentUser": "evt.Parsed.ParentUser",
                    "Imphash": "evt.Parsed.Imphash",
                    "Provider_Name": "evt.Parsed.ProviderName",
                    #taxonomy says it's imphash, but rules seem to use ImpHash
                    "imphash": "evt.Parsed.Imphash",                    
                    "md5": "evt.Parsed.md5",
                    "sha1": "evt.Parsed.sha1",
                    "sha256": "evt.Parsed.sha256",

                })
            ),
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_webproxy_fieldmapping",
                rule_conditions=[LogsourceCondition(category="proxy")],
                transformation=FieldMappingTransformation({
                    "c-uri": "evt.Parsed.uri",
                })
            ),
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                #fields:
                # a1-a7
                # PATH (?)


                identifier="crowdsec_linux_execve_fieldmapping",
                rule_conditions=[LogsourceCondition(service="auditd",product="linux",)],
                transformation=FieldMappingTransformation({
                    # generic auditd fields
                    "auid": "evt.Meta.auid",
                    "comm": "evt.Meta.comm",
                    "euid": "evt.Meta.euid",
                    "exe": "evt.Meta.exe",
                    "GID" : "evt.Meta.str_GID",
                    "gid": "evt.Meta.gid",
                    "pid": "evt.Meta.pid",
                    "ppid": "evt.Meta.ppid",
                    "res": "evt.Meta.res",
                    "ses": "evt.Meta.ses",
                    "sig": "evt.Meta.sig",
                    "subj": "evt.Meta.subj",
                    "tty": "evt.Meta.tty",
                    "type": "evt.Meta.auditd_type",
                    "UID" : "evt.Meta.str_UID",
                    "uid": "evt.Meta.uid",
                    #EXECVE related fields
                    "a1": "evt.Parsed.a1",
                    "a2": "evt.Parsed.a2",
                    "a3": "evt.Parsed.a3",
                    "a4": "evt.Parsed.a4",
                    "a5": "evt.Parsed.a5",
                    "a6": "evt.Parsed.a6",
                    "a7": "evt.Parsed.a7",
                    "a8": "evt.Parsed.a8",
                    "a9": "evt.Parsed.a9",
                    "a10": "evt.Parsed.a10",
                    #PATH related fields
                    "cap_fe": "evt.Meta.cap_fe",
                    "cap_fi": "evt.Meta.cap_fi",
                    "cap_fp": "evt.Meta.cap_fp",
                    "cap_frootid": "evt.Meta.cap_frootid",
                    "cap_fver": "evt.Meta.cap_fver",
                    "dev": "evt.Meta.dev",
                    "inode": "evt.Meta.inode",
                    "item": "evt.Meta.item",
                    "mode": "evt.Meta.mode",
                    "name": "evt.Meta.name",
                    "nametype": "evt.Meta.nametype",
                    "obj": "evt.Meta.obj",
                    "objtype": "evt.Meta.objtype",
                    "ogid": "evt.Meta.ogid",
                    "ouid": "evt.Meta.ouid",
                    "rdev": "evt.Meta.rdev",
                    #SERVICE_STOP related fields
                    #N/A

                })
            ),
        ],
    )
