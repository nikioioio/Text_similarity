from flask import Flask, jsonify, request
from flask_restful import  Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db['users']




def UserExist(username):
    if users.find({"username":username}).count() == 0:
        return False
    else:
        return True


def verifyPw(userName,password):

    if not UserExist(userName):
        return False

    passWrd = users.find({
        "username":userName
    })[0]["password"]

    retVerPass = bcrypt.checkpw(password.encode('utf8'), passWrd)

    return retVerPass

def countTokens(username):
    return users.find({"username": username})[0]["tokens"]

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                "status":301,
                "msg":"invalid Username"
            }
            return jsonify(retJson)

        hashed_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "username" : username,
            "password" : hashed_password,
            "tokens" : 6
        })

        retJson = {
            "status" : 200,
            "msg" : "You've successfully signed up to the api"
        }

        return jsonify(retJson)


class Detect(Resource):

    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not UserExist(username):
            retJson = {
                "status" : 301,
                "msg" :  "invalid username"
            }

            return jsonify(retJson)

        corect_pw = verifyPw(username,password)

        if not corect_pw:
            retJson = {
                "status":302,
                "msg":"invalid password"
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)

        if num_tokens<=0:
            retJson = {
                "status" : 303,
                "msg" : "You're out of tokens, please refill"
            }
            return jsonify(retJson)

        nlp = spacy.load('en_core_web_sm')

        text1 = nlp(text1)
        text2 = nlp(text2)

        ratio = text1.similarity(text2)

        retJson = {
            "status" : 200,
            "similarity" : ratio,
            "msg" : "similarity score is calculated"
        }



        users.update_one(
            {"username": username},
            {
                '$set': {
                    "tokens": num_tokens - 1
                }
            }
        )

        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_password"]
        refill_amount = postedData["refill"]


        if not UserExist(username):
            retJson = {
                "status" : 301,
                "msg" : "invalid username"
            }

            return jsonify(retJson)

        correct_password = "123xyz"

        if not password==correct_password:
            retJson = {
                "status" : 304,
                "msg" : "invalid admin password"
            }

            return  jsonify(retJson)



        users.update_one(
            {"username": username},
            {
                '$set': {
                    "tokens": refill_amount
                }
            }
        )

        retJson = {
            "status" : 200,
            "msg" : "Refilled successfully"
        }
        return jsonify(retJson)


api.add_resource(Register,"/register")
api.add_resource(Detect,"/detect")
api.add_resource(Refill,"/refill")

if __name__ == '__main__':
    app.run(host = '0.0.0.0' )
