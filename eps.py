from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import json


app = FastAPI()

file_storage_path = "/home/guru/ah-files"

@app.get("/active")
def read_active():
    try:
        with open(f'{file_storage_path}/Active.json', "r") as file:
            data = json.load(file)
        return JSONResponse(content=data, status_code=200)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Active.json not found")

@app.get("/disconnected")
def read_disconnected():
    try:
        with open(f'{file_storage_path}/Disconnected.json', "r") as file:
            data = json.load(file)
        return JSONResponse(content=data, status_code=200)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Disconnected.json not found")

@app.get("/all")
def read_all():
    try:
        current_data = []
        with open(f'{file_storage_path}/Active.json', "r") as active_file:
            current_data = json.load(active_file).get("Active Devices", [])

        disconnected_data = []
        with open(f'{file_storage_path}/Disconnected.json', "r") as disconnected_file:
            disconnected_data = json.load(disconnected_file).get("Disconnected Devices", [])

        return JSONResponse(content={"Active Devices": current_data, "Disconnected Devices": disconnected_data},
                            status_code=200)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Files not found")