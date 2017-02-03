#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    if username and USER_RE.match(username):
        return username.capitalize()

def valid_password(password):
    if password and PASS_RE.match(password):
        return password

def valid_email(email):
    return not email or MAIL_RE.match(email)

page_header = """
<!DOCTYPE html>
<html>
<head>
<title>Signup</title>
<style>
            .error {
                color: red;
            }
</style>
</head>
<body>
"""

page_footer = """
</body>
</html>
"""

content = """<form method="post">
            <table>
                <tbody><tr>
                    <td><label for="username">Username</label></td>
                    <td>
                        <input name="username" type="text" value="%(username)s" required="">
                        <span class="error">%(name_error)s</span>
                    </td>
                </tr>
                <tr>
                    <td><label for="password">Password</label></td>
                    <td>
                        <input name="password" type="password" required="">
                        <span class="error">%(password_error)s</span>
                    </td>
                </tr>
                <tr>
                    <td><label for="verify">Verify Password</label></td>
                    <td>
                        <input name="verify" type="password" required="">
                        <span class="error">%(verify_error)s</span>
                    </td>
                </tr>
                <tr>
                    <td><label for="email">Email (optional)</label></td>
                    <td>
                        <input name="email" type="email" value="%(email)s">
                        <span class="error">%(email_error)s</span>
                    </td>
                </tr>
            </tbody></table>
            <input type="submit">
        </form>"""

header = "<h1>Signup</h1>"

form = page_header + header + content + page_footer

class MainHandler(webapp2.RequestHandler):
    def write_form(self, name_error="", password_error="",
                    verify_error="", email_error="",
                    username="", email=""):
        self.response.write(form % {"name_error": name_error,
                                    "password_error": password_error,
                                    "verify_error": verify_error,
                                    "email_error": email_error,
                                    "username": username,
                                    "email": email})

    def get(self):
        self.write_form()

    def post(self):
        error = False
        username = cgi.escape(self.request.get("username"), quote=True)
        password = cgi.escape(self.request.get("password"), quote=True)
        verify = cgi.escape(self.request.get("verify"), quote=True)
        email = cgi.escape(self.request.get("email"), quote=True)

        params = dict(username = username,
                        email = email)

        valid_name = valid_username(username)
        valid_pass = valid_password(password)
        valid_address = valid_email(email)

        name_error = "Username not valid!"
        password_error = "Password not valid!"
        verify_error = "Passwords do not match!"
        email_error = "Email address not vaild!"



        if not valid_name:
            params["name_error"] = name_error
            error = True

        if not valid_pass:
            params["password_error"] = password_error
            error = True
        elif valid_pass != verify:
            params["verify_error"] = verify_error
            error = True

        if not valid_address:
            params['email_error'] = email_error
            error = True

        if error:
            self.write_form(**params)
        else:
            self.redirect("/welcome?username=" + username)

class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        username = cgi.escape(self.request.get("username"))

        title = "<title>Welcome</title>"
        message = "<h1>Welcome, " + username + "!</h1>"
        content = title + message
        self.response.write(content)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
