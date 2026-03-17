import os
from sigma.collection import SigmaCollection
from sigma_backend.sigma_engine import SigmaEngine

class SigmaDetector:
    def __init__(self, rule_dir):
        self.rule_dir=rule_dir
        self.rules=[]
        self._load_rules()

    def _load_rules(self):
        if not os.path.exists(self.rule_dir):
           print(f"Directory {self.rule_dir} does not exist")
           return

        for file in os.listdir(self.rule_dir):
            if file.endswith('.yml'):
                file_path=os.path.join(self.rule_dir,file)

                with open(file_path, 'r',encoding='utf-8') as f:
                    file_content=f.read()
                    try:
                        collection=SigmaCollection.from_yaml(file_content)
                        for rule in collection.rules:
                            self.rules.append(SigmaEngine(rule))
                    except Exception as e:
                        print(f"Error loading rule {file}: {e}")

        print(f"Loaded {len(self.rules)} rules from {self.rule_dir}")

    def analyze(self, log):
        match=False
        for rule in self.rules:
            if rule.process_rule(log):
                print(f"ALERT rule: {log['title']}")
                match=True
        return match