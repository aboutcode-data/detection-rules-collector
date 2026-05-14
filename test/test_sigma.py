#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from rules.sigma import CollectSigmaRulesPipeline


class TestCollectSigmaRulesPipeline:
    @pytest.fixture
    def sigma_pipeline(self):
        return CollectSigmaRulesPipeline()

    def test_single_sigma_rules_to_json(self, sigma_pipeline):
        yaml_text = """title: CVE-2020-5902 F5 BIG-IP Exploitation Attempt
id: 44b53b1c-e60f-4a7b-948e-3435a7918478
status: test
description: Detects the exploitation attempt of the vulnerability found in F5 BIG-IP and described in CVE-2020-5902
references:
    - https://support.f5.com/csp/article/K52145254
    - https://www.ptsecurity.com/ww-en/about/news/f5-fixes-critical-vulnerability-discovered-by-positive-technologies-in-big-ip-application-delivery-controller/
    - https://twitter.com/yorickkoster/status/1279709009151434754
    - https://www.criticalstart.com/f5-big-ip-remote-code-execution-exploit/
author: Florian Roth (Nextron Systems)
date: 2020-07-05
modified: 2023-01-02
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2020-5902
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection_base:
        cs-uri-query|contains:
            - '/tmui/'
            - '/hsqldb'
    selection_traversal:
        cs-uri-query|contains:
            - '..;/'
            - '.jsp/..'
    condition: selection_base and selection_traversal
falsepositives:
    - Unknown
level: critical"""
        assert sigma_pipeline.to_json(yaml_text) == [
            {
                "rule_metadata": {
                    "author": "Florian Roth (Nextron Systems)",
                    "date": "2020-07-05",
                    "id": "44b53b1c-e60f-4a7b-948e-3435a7918478",
                    "status": "test",
                    "title": "CVE-2020-5902 F5 BIG-IP Exploitation Attempt",
                },
                "rule_text": "title: CVE-2020-5902 F5 BIG-IP Exploitation Attempt\n"
                "id: 44b53b1c-e60f-4a7b-948e-3435a7918478\n"
                "status: test\n"
                "description: Detects the exploitation attempt of the "
                "vulnerability found in F5 BIG-IP\n"
                "  and described in CVE-2020-5902\n"
                "references:\n"
                "- https://support.f5.com/csp/article/K52145254\n"
                "- "
                "https://www.ptsecurity.com/ww-en/about/news/f5-fixes-critical-vulnerability-discovered-by-positive-technologies-in-big-ip-application-delivery-controller/\n"
                "- https://twitter.com/yorickkoster/status/1279709009151434754\n"
                "- "
                "https://www.criticalstart.com/f5-big-ip-remote-code-execution-exploit/\n"
                "author: Florian Roth (Nextron Systems)\n"
                "date: 2020-07-05\n"
                "modified: 2023-01-02\n"
                "tags:\n"
                "- attack.initial-access\n"
                "- attack.t1190\n"
                "- cve.2020-5902\n"
                "- detection.emerging-threats\n"
                "logsource:\n"
                "  category: webserver\n"
                "detection:\n"
                "  selection_base:\n"
                "    cs-uri-query|contains:\n"
                "    - /tmui/\n"
                "    - /hsqldb\n"
                "  selection_traversal:\n"
                "    cs-uri-query|contains:\n"
                "    - ..;/\n"
                "    - .jsp/..\n"
                "  condition: selection_base and selection_traversal\n"
                "falsepositives:\n"
                "- Unknown\n"
                "level: critical\n",
                "vulnerabilities": ["CVE-2020-5902"],
            }
        ]

    def test_multiple_sigma_rules_to_json(self, sigma_pipeline):
        yaml_text = """
title: Correlation - Mass Service Stoppage Associated with Cicada3301 Ransomware
id: 6039c5a5-d765-424c-b30d-cb391c9f76de
status: experimental
description: 'Detects repeated "service entered the stopped state" events, where numerous services are stopped as documented in the 2024 Morphisec Cicada3301 ransomware report.'
references:
    - https://blog.morphisec.com/cicada3301-ransomware-threat-analysis
author: 'Micah Babinski, Based on Morphisec report by Michael Gorelik (@smgoreli)'
date: 2024-09-07
tags:
    - attack.impact
    - attack.t1489
correlation:
    type: event_count
    rules:
        - important_service_stopped
    group-by:
        - Computer
    timespan: 10m
    condition:
        gte: 5
level: medium
---
title: Single Service Stoppage Associated with Cicada3301 Ransomware
name: important_service_stopped
id: ac3c528e-b4b5-4ea2-81bb-14385d104416
status: experimental
description: 'Detects a single "service entered the stopped state" events, where numerous services are stopped as documented in the 2024 Morphisec Cicada3301 ransomware report.'
author: 'Micah Babinski, Based on Morphisec report by Michael Gorelik (@smgoreli)'
date: 2024-09-07
tags:
    - attack.impact
    - attack.t1489
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7036
        Provider_Name: 'Service Control Manager'
        param1:
            - 'mepocs'
            - 'PDVFSService'
            - 'GxFWD'
            - 'MVarmor64'
            - 'memtas'
            - 'BackupExecVSSProvider'
            - 'SAPService'
            - 'VSNAPVSS'
            - 'veeam'
            - 'BackupExecAgentAccelerator'
            - 'SAP'
            - 'AcrSch2Svc'
            - 'svc$'
            - 'BackupExecAgentBrowser'
            - 'SAP$'
            - 'DefWatch'
            - 'backup'
            - 'BackupExecDiveciMediaService'
            - 'SAPD$'
            - 'ccEvtMgr'
            - 'sql'
            - 'BackupExecJobEngine'
            - 'SAPHostControl'
            - 'ccSetMgr'
            - 'vss'
            - 'BackupExecManagerService'
            - 'SAPHostExec'
            - 'SavRoam'
            - 'msexchange'
            - 'BackupExecRPCService'
            - 'QBCFMonitorService'
            - 'RTVscan'
            - 'sql$'
            - 'GxBlr'
            - 'QBDBMgrN'
            - 'QBFCService'
            - 'mysql'
            - 'GxVss'
            - 'QBIDPService'
            - 'Intuit.QuickBooks.FCS'
            - 'mysql$'
            - 'GxCIMgr'
            - 'AcronisAgent'
            - 'zhudongfangyu'
            - 'sophos'
            - 'GxCIMgrS'
            - 'VeeamNFSSvc'
            - 'stc_raw_agent'
            - 'MSExchange'
            - 'GxCVD'
            - 'VeeamDeploymentService'
            - 'BackupExecManagementService'
            - 'MSExchange$'
            - 'GXMMM'
            - 'VeeamTransportSvc'
            - 'CASAD2DWebSvc'
            - 'WSBExchange'
            - 'GxVssHWProv'
            - 'MVArmor'
            - 'CAARCUpdateSvc' 
        param2: 'stopped'
    condition: selection
falsepositives:
    - Unknown
level: informational
        """

        assert sigma_pipeline.to_json(yaml_text) == [
            {
                "rule_metadata": {
                    "author": "Micah Babinski, Based on Morphisec report by "
                    "Michael Gorelik (@smgoreli)",
                    "date": "2024-09-07",
                    "id": "6039c5a5-d765-424c-b30d-cb391c9f76de",
                    "status": "experimental",
                    "title": "Correlation - Mass Service Stoppage Associated "
                    "with Cicada3301 Ransomware",
                },
                "rule_text": "title: Correlation - Mass Service Stoppage Associated with "
                "Cicada3301 Ransomware\n"
                "id: 6039c5a5-d765-424c-b30d-cb391c9f76de\n"
                "status: experimental\n"
                'description: Detects repeated "service entered the stopped '
                'state" events, where numerous\n'
                "  services are stopped as documented in the 2024 Morphisec "
                "Cicada3301 ransomware report.\n"
                "references:\n"
                "- "
                "https://blog.morphisec.com/cicada3301-ransomware-threat-analysis\n"
                "author: Micah Babinski, Based on Morphisec report by Michael "
                "Gorelik (@smgoreli)\n"
                "date: 2024-09-07\n"
                "tags:\n"
                "- attack.impact\n"
                "- attack.t1489\n"
                "correlation:\n"
                "  type: event_count\n"
                "  rules:\n"
                "  - important_service_stopped\n"
                "  group-by:\n"
                "  - Computer\n"
                "  timespan: 10m\n"
                "  condition:\n"
                "    gte: 5\n"
                "level: medium\n",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {
                    "author": "Micah Babinski, Based on Morphisec report by "
                    "Michael Gorelik (@smgoreli)",
                    "date": "2024-09-07",
                    "id": "ac3c528e-b4b5-4ea2-81bb-14385d104416",
                    "status": "experimental",
                    "title": "Single Service Stoppage Associated with "
                    "Cicada3301 Ransomware",
                },
                "rule_text": "title: Single Service Stoppage Associated with Cicada3301 "
                "Ransomware\n"
                "name: important_service_stopped\n"
                "id: ac3c528e-b4b5-4ea2-81bb-14385d104416\n"
                "status: experimental\n"
                'description: Detects a single "service entered the stopped '
                'state" events, where numerous\n'
                "  services are stopped as documented in the 2024 Morphisec "
                "Cicada3301 ransomware report.\n"
                "author: Micah Babinski, Based on Morphisec report by Michael "
                "Gorelik (@smgoreli)\n"
                "date: 2024-09-07\n"
                "tags:\n"
                "- attack.impact\n"
                "- attack.t1489\n"
                "logsource:\n"
                "  product: windows\n"
                "  service: system\n"
                "detection:\n"
                "  selection:\n"
                "    EventID: 7036\n"
                "    Provider_Name: Service Control Manager\n"
                "    param1:\n"
                "    - mepocs\n"
                "    - PDVFSService\n"
                "    - GxFWD\n"
                "    - MVarmor64\n"
                "    - memtas\n"
                "    - BackupExecVSSProvider\n"
                "    - SAPService\n"
                "    - VSNAPVSS\n"
                "    - veeam\n"
                "    - BackupExecAgentAccelerator\n"
                "    - SAP\n"
                "    - AcrSch2Svc\n"
                "    - svc$\n"
                "    - BackupExecAgentBrowser\n"
                "    - SAP$\n"
                "    - DefWatch\n"
                "    - backup\n"
                "    - BackupExecDiveciMediaService\n"
                "    - SAPD$\n"
                "    - ccEvtMgr\n"
                "    - sql\n"
                "    - BackupExecJobEngine\n"
                "    - SAPHostControl\n"
                "    - ccSetMgr\n"
                "    - vss\n"
                "    - BackupExecManagerService\n"
                "    - SAPHostExec\n"
                "    - SavRoam\n"
                "    - msexchange\n"
                "    - BackupExecRPCService\n"
                "    - QBCFMonitorService\n"
                "    - RTVscan\n"
                "    - sql$\n"
                "    - GxBlr\n"
                "    - QBDBMgrN\n"
                "    - QBFCService\n"
                "    - mysql\n"
                "    - GxVss\n"
                "    - QBIDPService\n"
                "    - Intuit.QuickBooks.FCS\n"
                "    - mysql$\n"
                "    - GxCIMgr\n"
                "    - AcronisAgent\n"
                "    - zhudongfangyu\n"
                "    - sophos\n"
                "    - GxCIMgrS\n"
                "    - VeeamNFSSvc\n"
                "    - stc_raw_agent\n"
                "    - MSExchange\n"
                "    - GxCVD\n"
                "    - VeeamDeploymentService\n"
                "    - BackupExecManagementService\n"
                "    - MSExchange$\n"
                "    - GXMMM\n"
                "    - VeeamTransportSvc\n"
                "    - CASAD2DWebSvc\n"
                "    - WSBExchange\n"
                "    - GxVssHWProv\n"
                "    - MVArmor\n"
                "    - CAARCUpdateSvc\n"
                "    param2: stopped\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "- Unknown\n"
                "level: informational\n",
                "vulnerabilities": [],
            },
        ]
