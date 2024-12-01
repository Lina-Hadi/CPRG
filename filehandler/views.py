from unittest import result
from django.shortcuts import render

# Create your views here.

from django.http import JsonResponse
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

            def run_forensic_tools(file_path):
                results = {}  # Store results of each tool

                # Run `file` command to identify file type
                file_result = subprocess.run(['file', file_path], capture_output=True, text=True)
                results['file'] = file_result.stdout.strip()

                # Run `strings` command to extract readable strings
                strings_result = subprocess.run(['strings', file_path], capture_output=True, text=True)
                results['strings'] = strings_result.stdout[:500]  # Truncate output for readability

                # Run `hexdump` to display file content in hexadecimal
                hexdump_result = subprocess.run(['hexdump', '-C', file_path], capture_output=True, text=True)
                results['hexdump'] = hexdump_result.stdout[:500]  # Truncate output

                # Run `binwalk` to detect embedded files or executables
                binwalk_result = subprocess.run(['binwalk', file_path], capture_output=True, text=True)
                results['binwalk'] = binwalk_result.stdout.strip()

                # Run `exiftool` to extract metadata (useful for images, PDFs, etc.)
                exiftool_result = subprocess.run(['exiftool', file_path], capture_output=True, text=True)
                results['exiftool'] = exiftool_result.stdout.strip()

                # Run `zsteg` for steganographic data (if image)
                if file_path.lower().endswith(('.png', '.bmp')):
                   zsteg_result = subprocess.run(['zsteg', file_path], capture_output=True, text=True)
                   results['zsteg'] = zsteg_result.stdout.strip()

                # Run `pdfinfo` if the file is a PDF
                if file_path.lower().endswith('.pdf'):
                   pdfinfo_result = subprocess.run(['pdfinfo', file_path], capture_output=True, text=True)
                   results['pdfinfo'] = pdfinfo_result.stdout.strip()

                # Run `ffmpeg` to extract metadata for media files
                ffmpeg_result = subprocess.run(['ffmpeg', '-i', file_path], capture_output=True, text=True, stderr=subprocess.STDOUT)
                results['ffmpeg'] = ffmpeg_result.stdout.strip()

                # Run `mediainfo` for detailed metadata (video/audio files)
                mediainfo_result = subprocess.run(['mediainfo', file_path], capture_output=True, text=True)
                results['mediainfo'] = mediainfo_result.stdout.strip()

                # Run `mp3info` if the file is an MP3
                if file_path.lower().endswith('.mp3'):
                  mp3info_result = subprocess.run(['mp3info', file_path], capture_output=True, text=True)
                  results['mp3info'] = mp3info_result.stdout.strip()

                # Run `soxi` for audio file information
                soxi_result = subprocess.run(['soxi', file_path], capture_output=True, text=True)
                results['soxi'] = soxi_result.stdout.strip()

                # Run `mp4champs` if the file is an MP4
                if file_path.lower().endswith('.mp4'):
                  mp4champs_result = subprocess.run(['mp4champs', '-i', file_path], capture_output=True, text=True)
                  results['mp4champs'] = mp4champs_result.stdout.strip()

                # Combine tool results to determine if malicious
                malicious_flag = "malicious" in " ".join(results.values()).lower()
                results['malicious'] = ("Security tool flagged this file as malicious" if malicious_flag else "No security tool flagged this file as malicious")

                return results


            analysis_result = run_forensic_tools(file_path)

            # Clean up file after processing
            os.remove(file_path)

            # Return the response
            return JsonResponse(results)
        return Response('..')

