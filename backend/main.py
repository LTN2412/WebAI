from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from router import user
from fastapi.staticfiles import StaticFiles
import torch
from torchvision import transforms
from model.model import effB1
from PIL import Image
import requests
from typing import Annotated
from fastapi import Depends
from dependencies import check_valid_token, get_user_GG


app = FastAPI()
origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(user.router)
app.mount('/img', StaticFiles(directory='img'))
model = effB1()
model.load_state_dict(torch.load('./model/effB1.pth'))
data_transforms = transforms.Compose([
    transforms.Resize((256, 256)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])])

classes = ['pizza', 'steak', 'sushi']


@app.get('/')
def hello():
    return {
        'userName': 'ltn2412',
        'fullName': 'Le Thanh Nhat'
    }


@app.post('/predict')
async def get_img(request: Request, file: UploadFile = File(...)):
    contents = await file.read()
    with open('./img/test.jpg', 'wb') as f:
        f.write(contents)
    img = Image.open('./img/test.jpg')
    img_transform = data_transforms(img).unsqueeze(dim=0)
    model.eval()
    with torch.inference_mode():
        y_logits = model(img_transform)
        y_predict = torch.softmax(y_logits, dim=1).argmax(dim=1)
    return {'predict': classes[y_predict]}


@app.post('/test')
async def test(file: UploadFile = File(...)):
    return ({
        'name': 'test',
        'hi': 'hi'
    })


@app.get('/token')
async def data_user(res: Annotated[dict, Depends(get_user_GG)]):
    return res
