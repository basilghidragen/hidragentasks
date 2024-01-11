from django.db import models

# Create your models here.
class UserDetails(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=500)
    token=models.JSONField(null=True,blank=True)

class Category(models.Model):
    category_name = models.CharField(max_length=50)
    created_at = models.DateField(auto_now_add=True)
    
class Products(models.Model):
    product_name = models.CharField(max_length=50)
    product_price = models.FloatField()
    image = models.ImageField(upload_to='images/',default=None)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    user = models.ForeignKey(UserDetails, on_delete=models.CASCADE)