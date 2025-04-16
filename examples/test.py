from mitreattack.stix20 import MitreAttackData

def get_unique_mitigation_ids(attack_data, filters: list[str], domain: str = "enterprise-attack"):
    all_techniques = []

    if domain == "enterprise-attack" or domain == "mobile-attack":
        for f in filters:
            techniques = attack_data.get_techniques_by_platform(platform=f, remove_revoked_deprecated=True)
            all_techniques.extend(techniques)
    elif domain == "ics-attack":
        for f in filters:
            techs_for_asset = attack_data.get_techniques_targeting_asset(f)
            all_techniques.extend([t["object"] for t in techs_for_asset])
    else:
        raise ValueError("Unsupported domain")

    print(f"Total techniques collected: {len(all_techniques)}")

    # Deduplicate techniques by STIX ID
    seen_tech_ids = set()
    unique_techniques = []
    for tech in all_techniques:
        if tech["id"] not in seen_tech_ids:
            seen_tech_ids.add(tech["id"])
            unique_techniques.append(tech)

    # Get mitigations
    all_mitigations = attack_data.get_all_mitigations_mitigating_all_techniques()
    mitigation_ids = set()

    for tech in unique_techniques:
        tech_id = tech["id"]
        mitigations = all_mitigations.get(tech_id, [])
        for m in mitigations:
            mit_id = attack_data.get_attack_id(m["object"]["id"])
            if mit_id:
                mitigation_ids.add(mit_id.lower())

    return mitigation_ids

if __name__ == "__main__":

    liste = []

    attack_data = MitreAttackData("enterprise-attack.json")  # or mobile-attack.json / ics-attack.json
    platforms = ["Windows"]
    liste.extend(get_unique_mitigation_ids(attack_data, filters=platforms, domain="enterprise-attack"))
    # Example for ICS assets (you'd use asset STIX IDs)
    attack_data = MitreAttackData("ics-attack.json")
    assets = ["x-mitre-asset--3a95f7e4-4877-4967-b2e8-e287976c3e64"]
    liste.extend(get_unique_mitigation_ids(attack_data, filters=assets, domain="ics-attack"))
    
    print(liste)
    # Example for Mobile technologies
    # mobile_techs = ["Android", "iOS"]
    # get_unique_mitigation_ids(attack_data, filters=mobile_techs, domain="mobile-attack")

