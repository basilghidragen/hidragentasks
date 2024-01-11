from django.urls import path
from .views import CategoryAPIView,ProductsAPIView,UserDetailsAPIView,UserLoginView,UserLogoutView

urlpatterns = [ 
               
    # UserAuthentication
    
    path('user/login/',UserLoginView.as_view(),name='userlogin'),
    path('user/logout/',UserLogoutView.as_view(),name='userlogout'),
          
    # UserDetails
    
    path('user/create/',UserDetailsAPIView.as_view(),name='usercreateview'),
    path('user/list/',UserDetailsAPIView.as_view(),name='userlistview'),
    path('user/update/<int:pk>/',UserDetailsAPIView.as_view(),name='userupdateviews'),
    path('user/delete/<int:pk>/',UserDetailsAPIView.as_view(),name='userdeleteviews'), 
      
    # Category
    
    path('category/create/',CategoryAPIView.as_view(),name='categorycreateviews'),
    path('category/list/',CategoryAPIView.as_view(),name='categorylistviews'),
    path('category/update/<int:pk>/',CategoryAPIView.as_view(),name='categoryupdateviews'),
    path('category/delete/<int:pk>/',CategoryAPIView.as_view(),name='categorydeleteviews'),
    
    # Products
    
    path('product/create/',ProductsAPIView.as_view(),name='productcreateview'),
    path('product/list/',ProductsAPIView.as_view(),name='productlistview'),
    path('product/update/<int:pk>/',ProductsAPIView.as_view(),name='productupdateview'),
    path('product/delete/<int:pk>/', ProductsAPIView.as_view(), name='productdeleteview'),
    
    
]
            