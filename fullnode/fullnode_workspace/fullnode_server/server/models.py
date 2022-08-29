from django.db import models

# Create your models here.
class Cert(models.Model):
    hash = models.CharField("Cert_Hash", max_length=100, primary_key=True)
    data = models.TextField("Cert_Data")