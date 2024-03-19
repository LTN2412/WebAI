from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

pwd = '?????'
SECRET_KEY = '6cb44af8db458e82d66b1f7abf76c7c56a52f346beaa43ea2c9061196e49cf56'
HASH_ALGORITHM = 'bcrypt'
JWT_ALGORITHM = 'HS256'
TOKEN_URL = 'user/token'
uri = f"mongodb+srv://ltn2412:{pwd}@cluster0.ovlrk4l.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(uri, server_api=ServerApi('1'))
db = client['User']
