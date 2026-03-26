import re
import time

from sigma_processing.handlers import ValueCountHandler, EventCountHandler

class SigmaRule:
    def __init__(self,rule):
        self.rule = rule
        self.id = getattr(rule, "name", None)
        self.title = getattr(rule, "title", "Untitled")

        if hasattr(self.rule.detection, 'to_dict'):
            self.selection = self.rule.detection.to_dict().get("selection", {})
        else:
            self.selection = {}

        self.correlation = getattr(rule, "correlation", None)
        self.handler = self._create_handler()

    def _create_handler(self):

        if not self.correlation:
            return None

        timespan_raw = getattr(self.correlation, 'timespan', '1m')
        res = re.findall(r'\d+', str(timespan_raw))
        num = int(res[0]) if res else 60
        ts = num * 60 if 'm' in str(timespan_raw).lower() else num

        condition = getattr(self.correlation, 'condition', {})

        if isinstance(condition, dict):
            threshold = condition.get('gte') or condition.get('gt', 0) + 1 or condition.get('value')
        else:
            threshold = condition

        final_threshold = int(threshold) if threshold is not None else 100

        corr_type = getattr(self.correlation, 'type', None)
        if corr_type == 'value_count':
            return ValueCountHandler(final_threshold, ts)
        elif corr_type == 'event_count':
            return EventCountHandler(final_threshold, ts)

        return None

    def _matches_selection(self, log):
        if not self.selection:
            return False

        for field, expected_value in self.selection.items():
            value=log.get(field)
            if str(value).lower() != str(expected_value).lower():
                return False
        return True

    def process_rule(self, log, is_correlation_trigger=False):
        match = True if (is_correlation_trigger and self.correlation) else self._matches_selection(log)

        if not self.handler:
            return match

        if match:
            group_by = getattr(self.correlation, 'group_by', None) or getattr(self.correlation, 'group-by', None)
            if not group_by:
                return False

            group_field = group_by[0]
            group_key = log.get(group_field)

            if not group_key:
                return False

            is_alert = False
            corr_type = getattr(self.correlation, 'type', None)

            if corr_type == 'value_count':
                condition = getattr(self.correlation, 'condition', {})
                value_field = condition.get('field') if isinstance(condition, dict) else None

                if value_field:
                    collected_value = log.get(value_field)
                    is_alert = self.handler.evaluate(group_key, collected_value)
            else:
                is_alert = self.handler.evaluate(group_key)

            if is_alert:
                self._set_flags(log)
                return True

        return False

    def _set_flags(self,log):

        log['is_alert']=True
        log['sigma_rule_name']=self.title
