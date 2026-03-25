import time

class EventCountHandler:
    def __init__(self, threshold, timespan):
        self.threshold = threshold
        self.timespan = timespan
        self.events = {}
        print(f"[DEBUG] Handler creat cu PRAG: {self.threshold} și TIMP: {self.timespan}s")

    def evaluate(self, group_key):
        if not group_key:
            return False

        now = time.time()
        if group_key not in self.events:
            self.events[group_key] = []

        self.events[group_key].append(now)

        self.events[group_key] = [t for t in self.events[group_key] if now - t <= self.timespan]

        if len(self.events[group_key]) >= self.threshold:
            return True
        return False

class ValueCountHandler:
    def __init__(self, threshold, timespan):
        self.threshold = threshold
        self.timespan = timespan
        self.events = {}

    def evaluate(self, group_key, collected_value):
        if not group_key:
            return False

        now = time.time()
        if group_key not in self.events:
            self.events[group_key] = []

        self.events[group_key].append((now, collected_value))

        self.events[group_key] = [item for item in self.events[group_key] if now - item[0] <= self.timespan]

        unique_values = {item[1] for item in self.events[group_key]}

        if len(unique_values) >= self.threshold:
            return True
        return False