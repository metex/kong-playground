# Import the server module

import http.server
from io import BytesIO

## Run python3 -m http.server 8000 --bind 127.0.0.1 
# Set the hostname

HOST = "0.0.0.0"

# Set the port number

PORT = 4000

# Datastore, password is always password=1234567
users = [
    {'id_user': '1', 'user_token': 'j6BhUMiG2RKP1eVTsqWbl0woT', 'firstname': 'John', 'lastname': "Doe", 'email': 'john1@gmail.com', 'password': '$2y$10$1/xlmIBAoz1SMgMTyAtr8eKhE33Truhg/t5xjic6VXclhgfEINv4i', 'verified': True, 'active': True, 'lang': 'pt', 'updated_at': '2022-06-09 11:10:22', 'created_at': '2022-06-09 11:10:22'},
    {'id_user': '2', 'user_token': 'hCnuiLISUFYzD1e54ea6O54Ox', 'firstname': 'John', 'lastname': "Doe", 'email': 'john2@gmail.com', 'password': '$2y$10$1/xlmIBAoz1SMgMTyAtr8eKhE33Truhg/t5xjic6VXclhgfEINv4i', 'verified': True, 'active': True, 'lang': 'pt', 'updated_at': '2022-06-09 11:10:22', 'created_at': '2022-06-09 11:10:22'},
]

# Define class to display the index page of the web server

class PythonServer(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        """Handle GET."""
        if self.path == '/':
            
            self.path = 'testHTML.html'

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        """Handle POST."""
        if self.path != "/interact":
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            self.send_response(200)
            self.end_headers()
            response = BytesIO()
            response.write(b'This is POST request. ')
            response.write(b'Received: ')
            response.write(body)
            self.wfile.write(response.getvalue())

# Declare object of the class

webServer = http.server.HTTPServer((HOST, PORT), PythonServer)


# Print the URL of the webserver

print("Server started http://%s:%s" % (HOST, PORT))


try:

    # Run the web server

    webServer.serve_forever()

except KeyboardInterrupt:

    # Stop the web server

    webServer.server_close()

    print("The server is stopped.")