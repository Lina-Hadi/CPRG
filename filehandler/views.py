from django.shortcuts import render

# Create your views here.

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import FileUploadSerializer
import subprocess
import os

class FileUploadView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():
            uploaded_file = serializer.validated_data['file']

            # Save the file
            file_path = f"uploaded_files/{uploaded_file.name}"
            with open(file_path, 'wb+') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)

            # Example: Run a steganography tool (replace with actual tool)
            result = subprocess.run(['strings', file_path], capture_output=True, text=True)

            # Clean up file after processing
            os.remove(file_path)

            # Return the tool output
            return Response({'title': "strings",'output': result.stdout}, status=status.HTTP_200_OK)

        return Response('..')

