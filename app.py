from flask import Flask, Blueprint,render_template, request, redirect, session

from rgz import rgz

app = Flask(__name__)
app.secret_key = "123"
app.register_blueprint(rgz)
