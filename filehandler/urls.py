from django.urls import path
from .views import FileUploadView

urlpatterns = [
    path('upload/', FileUploadView.as_view(), name='file-upload'),
]
