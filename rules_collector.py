import sys

from rules import sigma
from rules import clamav
from rules import yara
from rules import suricata

if __name__ == "__main__":
    RULES_REGISTRY = [
        # Sigma Rules
        sigma.SigmaHQImproverPipeline,
        sigma.SigmaSamuraiMDRImproverPipeline,
        sigma.SigmaMbabinskiImproverPipeline,
        sigma.P4T12ICKSigmaImproverPipeline,
        # Yara Rules
        yara.ProtectionsArtifactsYara,
        yara.YaraRulesYara,
        yara.XumeiquerForensicsYara,
        yara.ReversinglabsYaraRules,
        yara.AdvancedThreatResearchYara,
        yara.BartblazeYaraRules,
        yara.GodaddyYaraRules,
        yara.SupportIntelligenceIcewaterYara,
        yara.Jeff0FalltradesSignaturesYara,
        yara.TjnelRepoYara,
        yara.JpcertccJpcertYara,
        yara.MikesxrsOpenSourceYaraRules,
        yara.FboldewinYaraRules,
        yara.H3x2bYaraRules,
        yara.RoadwyDefenderYara,
        yara.MthchtThreatHuntingKeywordsYara,
        yara.Neo23x0SignatureBaseYara,
        yara.MalpediaSignatorRulesYara,
        yara.BaderjYara,
        yara.DeadbitsYaraRules,
        yara.PmelsonYaraRules,
        yara.SbousseadenYaraHunts,
        yara.EmbeeResearchYaraRules,
        yara.RussianPanda95YaraRules,
        yara.AilProjectAilYaraRules,
        yara.MalgamyYaraRules,
        yara.ElceefYaraRulz,
        yara.TenableYaraRules,
        yara.Dr4k0niaYaraRules,
        yara.Umair9747YaraRules,
        # Suricata Rules
        suricata.SudohyakSuricataPipeline,
        suricata.OISFSuricataPipeline,
        # ClamV Rules
        clamav.ClamAVPipeline,
    ]

    for pipeline in RULES_REGISTRY:
        rule_collector = pipeline()
        status_code, error_msg = rule_collector.execute()
        print(error_msg)

    sys.exit(0)
