import time

class EventCountHandler:
    def __init__(self,threshold,timespan):
        self.threshold=threshold
        self.timespan=timespan
        self.events={} #{group_key:[packet, packet2, ...],group-key2:[packet, packet2, ...], ...}

    def evaluate(self, group_key):
        if not group_key:
            return False

        now=time.time()
        if group_key not in self.events:
            self.events[group_key]=[]

        self.events[group_key].append(now)
        self.events[group_key]=[t for t in self.events[group_key] if now -t <= self.timespan]

        return len(self.events[group_key]) >= self.threshold

class ValueCountHandler:
    def __init__(self,threshold,timespan):
        self.threshold=threshold
        self.timespan=timespan
        self.events={}

    def evaluate(self, group_key, collected_value):
        if not group_key:
            return False

        now=time.time()
        if group_key not in self.events:
            self.events[group_key]=[]

        self.events[group_key].append((now,collected_value))
        self.events[group_key] = [item for item in self.events[group_key] if now - item[0] <= self.timespan]

        unique_values={item[1] for item in self.events[group_key]}

        return len(unique_values) >= self.threshold


