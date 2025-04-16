from mitreattack.stix20 import MitreAttackData

def list_all_ics_assets(stix_path: str):
    attack_data = MitreAttackData(stix_path)
    assets = attack_data.get_assets(remove_revoked_deprecated=True)

    print(f"Found {len(assets)} assets:\n")
    for asset in assets:
        print(f"{asset['name']} --> {asset['id']}")

# Example usage
if __name__ == "__main__":
    list_all_ics_assets("ics-attack.json")  # Replace with your actual path
