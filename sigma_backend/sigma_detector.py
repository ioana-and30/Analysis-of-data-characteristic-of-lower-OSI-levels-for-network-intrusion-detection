import os
from sigma.collection import SigmaCollection

from sigma_backend.sigma_engine import SigmaEngine


class SigmaDetector:
    def __init__(self, rule_dir):
        self.rule_dir=rule_dir
        self.counters={}
        self.rules=[]
        self._load_rules()

    def _load_rules(self):
        import yaml
        from sigma.collection import SigmaCollection

        for file in sorted(os.listdir(self.rule_dir)):
            if not file.endswith('.yml'):
                continue

            file_path = os.path.join(self.rule_dir, file)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                raw_data = yaml.safe_load(content)

            if 'detection' in raw_data:
                try:
                    collection = SigmaCollection.from_yaml(content)
                    for rule in collection.rules:
                        self.rules.append(SigmaEngine(rule))
                except Exception as e:
                    print(f"Error {file}: {e}")

            elif 'correlation' in raw_data:
                mock_rule = type('SigmaRule', (object,), {
                    'name': raw_data.get('name') or raw_data.get('title').lower().replace(' ', '_'),
                    'title': raw_data.get('title', 'Untitled'),
                    'tags': raw_data.get('tags', []),
                    'correlation': type('Struct', (object,), raw_data['correlation']),
                    'detection': type('MockDet', (object,), {"to_dict": lambda: {"selection": {}}})
                })
                self.rules.append(SigmaEngine(mock_rule))

    def analyze(self, log):
        found_match = False
        for engine in self.rules:
            if engine.process_rule(log):
                event_name = engine.id

                for corr_engine in self.rules:
                    if corr_engine.correlation:
                        sources = getattr(corr_engine.correlation, 'rules', [])
                        if event_name in sources:
                            if corr_engine.process_rule(log):
                                print(f"\n[!!!] ALERTĂ BACKEND: {corr_engine.title} [!!!]")
                                found_match = True
        return found_match