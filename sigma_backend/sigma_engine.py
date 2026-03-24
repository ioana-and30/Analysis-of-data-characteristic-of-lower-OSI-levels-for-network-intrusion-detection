import re
import time

from sigma_backend.handlers import ValueCountHandler, EventCountHandler


class SigmaEngine:
    def __init__(self,rule):
        self.rule=rule
        self.id=getattr(rule,"name")
        self.title=getattr(rule,"title")

        self.selection=self.rule.detection.to_dict().get("selection",{})

        self.correlation=getattr(rule,"correlation", None)
        self.handler=self._create_handler()

    def _create_handler(self):

        if not self.correlation:
            return None

        timespan=self.correlation.timespan
        res=re.findall(r'\d+',str(timespan))
        num=int(res[0]) if res else 60
        ts=num*60 if 'm' in str(timespan) else num

        condition=self.correlation.condition
        threshold=20
        if isinstance(condition,dict):
            threshold=condition.get('gte') or condition.get('value') or 20

        if self.correlation.type=='value_count':
            return ValueCountHandler(threshold,ts)
        elif self.correlation.type=='event_count':
            return EventCountHandler(threshold,ts)
        return None

    def _matches_selection(self, log):
        if not self.selection:
            return False

        for field, expected_value in self.selection.items():

            value=log.get(field)
            if str(value).lower() != str(expected_value).lower():
                return False
            return True

    def process_and_flag(self, log):
        if not self._matches_selection(log):
            return False

        if not self.handler:
            self._set_flags(log)
            return True

        try:
            group_field=self.correlation.group_by[0]
            group_key=log.get(group_field)

            if not group_key:
                return False

            is_alert=False

            if self.correlation.type=='value_count':
                value=self.correlation.condition.get('field') or self.correlation.generate[0]
                observed_value=log.get(value)

                if observed_value:
                    is_alert=self.handler.evaluate(group_key,observed_value)

                else:
                    is_alert=self.handler.evaluate(group_key)

                if is_alert:
                    self._set_flags(log)
                    return True

        except Exception as e:
            print(f"Error processing rule {self.title}: {e}")

        return False

    def _set_flags(self,log):

        log['is_alert']=True
        log['sigma_rule_name']=self.title
        log['alert_timestamp']=time.strftime('%H:%M:%S')