import jwt

client_secret="7835cd41-71fb-4f2c-832c-cc71d2ca6adc"

rec_id_token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItMUNSWnFjak5YSVZ2N3pxRVY1c1VYTVB3eWYwS2h3cDhCZEF2bDQxV3NJIn0.eyJqdGkiOiI0NTFiYTkwOS1lMGM1LTRmNDgtOTdiZS1kMDRkMzY2ODU1NjAiLCJleHAiOjE1NjQ0MjQ2MTIsIm5iZiI6MCwiaWF0IjoxNTY0NDI0MzEyLCJpc3MiOiJodHRwczovL3Nzby1kZXYuYXBwcy5iYW5lc3Rlcy5iLmJyL2F1dGgvcmVhbG1zL3NmYi1kZXYiLCJhdWQiOiJ6ZW52aWEtZ2VyZW5jaWFkb3Itd2ViIiwic3ViIjoiZjpkNWRjNTMyZi1hZjUyLTQ4ZTEtOTQwZS1kYTAyMjMxMjNkODA6MTAwMDEiLCJ0eXAiOiJJRCIsImF6cCI6InplbnZpYS1nZXJlbmNpYWRvci13ZWIiLCJhdXRoX3RpbWUiOjE1NjQ0MjQyOTMsInNlc3Npb25fc3RhdGUiOiI1NzBhOGZlMC0xOTM0LTQ2ZWQtYWVjZS1jNTFkZmM5NjY2MzkiLCJhY3IiOiIxIiwibmFtZSI6IjEwMDAxIE1HSiIsInByZWZlcnJlZF91c2VybmFtZSI6IjEwMDAxIiwiZ2l2ZW5fbmFtZSI6IjEwMDAxIiwiZmFtaWx5X25hbWUiOiJNR0oiLCJlbWFpbCI6ImFjbWVsb0BiYW5lc3Rlcy5jb20uYnIifQ.gfwF297NZvCWH7LCzLqFNycjgbObzPcwGQDy1-yhI2DhwmxkAcXd0vRNLV48DllKRbHHMiSvvW5BLCTTy7f14jTw_NtpybV-GfWm5cH-OurcMtqukosSFhaGbIWNNIIsXaioa9z87wHJfM76hnF34EdT6HsjdDVxiusqkNcp_g6VZzCcXMzYJWnQUAxqFgSqoLmtwm8tOSQ9uxK7SmGLaQvRXYNB4Qldul8xC8UKkUFTdo3wNZrFI5eKU1Y2ZOac3YBrORTG2Z8J40u1bBpYK6gA1aFf5fgjBSdD_0z4KdmmQocSlkGr_SD-8fdAP4WpeLun53s7zze6xMmGJhCUOQ"

id_token_headers = jwt.get_unverified_header(rec_id_token)
#id_token = jwt.decode(rec_id_token, client_secret, algorithms=['HS256'])
id_token = jwt.decode(rec_id_token, verify=False)
result_string = str(id_token_headers) + "<br/>" + str(id_token)
print("id_token decoded: {}".format(result_string))
