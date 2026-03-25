import os

import yaml
from sigma.collection import SigmaCollection

from sigma_processing.sigma_rule import SigmaRule

class SigmaBackend:
    def __init__(self, rule_dir):
        self.rule_dir=rule_dir
        self.rules=[]
        self._load_rules()

    def _load_rules(self):
        for file in sorted(os.listdir(self.rule_dir)):
            if not file.endswith('.yml'): continue

            path = os.path.join(self.rule_dir, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                raw_data = yaml.safe_load(content)

            if 'detection' in raw_data and 'correlation' not in raw_data:
                try:
                    collection = SigmaCollection.from_yaml(content)
                    for rule in collection.rules:
                        self.rules.append(SigmaRule(rule))
                except Exception as e:
                    print(f"Error {file}: {e}")
            elif 'correlation' in raw_data:
                mock_rule = type('SigmaRule', (object,), {
                    'name': raw_data.get('name') or raw_data.get('title').lower().replace(' ', '_'),
                    'title': raw_data.get('title', 'Untitled'),
                    'correlation': type('Struct', (object,), raw_data['correlation']),
                    'detection': type('MockDet', (object,), {"to_dict": lambda: {"selection": {}}})
                })
                self.rules.append(SigmaRule(mock_rule))

    def analyze(self, log):
        found_any_alert = False
        matched_event_ids = []

        for engine in self.rules:
            if not engine.correlation:
                if engine.process_rule(log):
                    matched_event_ids.append(engine.id)

        for event_id in matched_event_ids:
            for engine in self.rules:
                if engine.correlation:
                    sources = getattr(engine.correlation, 'rules', [])

                    if event_id in sources:
                        if engine.process_rule(log, is_correlation_trigger=True):
                            print(f"\n[!!!] ALERTĂ DETECTATĂ: {engine.title} [!!!]")
                            found_any_alert = True
        return found_any_alert