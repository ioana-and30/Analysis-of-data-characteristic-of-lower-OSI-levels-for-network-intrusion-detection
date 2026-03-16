import os

import yaml


class SigmaEngine:
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.rules=[]

    def load_rules(self,path):
        self.rules=[]

        if not os.path.exists(path):
            raise FileNotFoundError(f"Rules directory not found: {path}")

        for file in os.listdir(path):
            if file.endswith('.yml'):
                with open(os.path.join(path, file), 'r') as f:
                    try:
                        rule_data = yaml.safe_load(f)
                        if rule_data:
                            self.rules.append(rule_data)
                    except Exception as e:
                        print(f"Error loading rule {file}: {e}")
        return self.rules

    def print_rules(self):
        for rule in self.rules:
            print(rule)
