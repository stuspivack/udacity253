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
import os
import webapp2
import jinja2
from google.appengine.ext import db
import re
import hashlib
import hmac
import string
import random
import json

secret = 'hunter2'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
BLANK_RE = re.compile(r"^[\s]*$")

def valid_username(username):
    return USER_RE.match(username)

def valid_pass(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def blank(text):
    return BLANK_RE.match(text)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class Blog(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):
    def render_front(self):
        blogPosts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        self.render("front.html", blogPosts = blogPosts)
    def get(self):
        self.render_front()

class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        title = self.request.get("subject")
        body = self.request.get("content")

        if body and title:
            blogPost = Blog(title = title, body = body)
            blogPost.put()
            postId = blogPost.key().id()
            self.redirect("/" + str(postId))
        else:
            error = ("Please enter a title and a body.")
            self.render("newpost.html", title= title, body = body, error = error)

class Permalink(Handler):
    def get(self, postIdstr):
        postId = int(postIdstr)
        blogPost = Blog.get_by_id(postId)
        self.render('permalink.html', title = blogPost.title, body = blogPost.body)

def hmac_str(string):
    return hmac.new(secret, string).hexdigest()

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

def hash_str(s):
        return hashlib.sha256(s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val

class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        password2 = self.request.get('verify')
        email = self.request.get('email')
        isNewUser = True
        oldUsers = db.GqlQuery("SELECT * FROM Users")
        for userc in oldUsers:
            if userc.username == user:
                isNewUser = False
                break
        if (valid_username(user) and (valid_email(email) or blank(email))
            and valid_pass(password) and password == password2 and isNewUser):
            salt = make_salt()
            hashedPass = make_pw_hash(user, password, salt)
            newUser = Users(username = user, password = hashedPass, email = email)
            newUser.put()
            userId = str(newUser.key().id())
            hashedId = make_secure_val(userId)
            self.response.headers.add_header('Set-Cookie', 'userId=%s; Path=/' % hashedId)    
            self.redirect("/welcome")
        else:
            if not isNewUser:
                userError = "Username is not available"
            elif valid_username(user):
                userError = ""
            else:
                userError = "Invalid username"
            if valid_email(email) or blank(email):
                emailError = ""
            else:
                emailError = "Invalid email"
            if not valid_pass(password):
                passError = "Invalid password"
                matchError = ""
            elif password != password2:
                matchError = "Passwords do not match"
                passError = ""
            else:
                passError = ""
                matchError = ""
            self.render('signup.html', user = user, email = email, userError = userError, passError = passError,
                        matchError = matchError, emailError = emailError)

class WelcomePage(Handler):
    def get(self):
        hashedId = self.request.cookies.get('userId')
        userIdStr = check_secure_val(hashedId)
        if check_secure_val(hashedId):
            userId = int(userIdStr)
            aUser = Users.get_by_id(userId)
            self.render('welcome.html', user = aUser.username)
        else:
            self.redirect('/signup')

class LoginPage(Handler):
    def get(self):
        self.render('login.html')
    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        thisUser = Users.all().filter('username =', user).get()
        if thisUser:
            if valid_pw(user, password, thisUser.password):
                userId = str(thisUser.key().id())
                hashedId = make_secure_val(userId)
                self.response.headers.add_header('Set-Cookie', 'userId=%s; Path=/' % hashedId)
                self.redirect("/welcome")
        self.render("login.html", passError = "Invalid Login")

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'userId=; Path=/')
        self.redirect('/signup')

class MainJsonPage(Handler):
    def get(self):
        self.response.headers.add_header('Content-Type', 'application/json; charset: UTF-8')
        postList = []
        blogPosts = Blog.all()
        for blogPost in blogPosts:
            postList.append({'content': blogPost.body, 'created': blogPost.created.strftime("%b %d, %Y"), 'subject': blogPost.title})
        blogsJson = json.dumps(postList)
        self.response.out.write(blogsJson)

class IndividualJsonPage(Handler):
    def get(self, postIdstr):
        postId = int(postIdstr)
        blogPost = Blog.get_by_id(postId)
        postDict = {'content': blogPost.body, 'created': blogPost.created.strftime("%b %d, %Y"), 'subject': blogPost.title}
        self.response.headers.add_header('Content-Type', 'application/json; charset: UTF-8')
        blogJson = json.dumps(postDict)
        self.response.out.write(blogJson)


app = webapp2.WSGIApplication([(r'/', MainPage),
                               (r'/newpost', NewPost),
                               (r'/(\d+)', Permalink),
                               (r'/signup', Signup),
                               (r'/welcome', WelcomePage),
                               (r'/login', LoginPage),
                               (r'/logout', LogoutPage),
                               (r'/\.json', MainJsonPage),
                               (r'/(\d+)\.json', IndividualJsonPage)],
                              debug=True)

