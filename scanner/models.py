# from django.db import models
# Create your models here.

from django.db import models
import json

class ScanResult(models.Model):
    url = models.URLField(max_length=500)
    scanned_at = models.DateTimeField(auto_now_add=True)
    score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20)
    results_json = models.TextField(default='{}')

    class Meta:
        ordering = ['-scanned_at']

    def get_results(self):
        return json.loads(self.results_json)

    def __str__(self):
        return f"{self.url} - {self.risk_level} - {self.scanned_at.strftime('%Y-%m-%d %H:%M')}"