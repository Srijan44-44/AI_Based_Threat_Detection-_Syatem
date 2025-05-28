from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/threat-log")
async def receive_threat_log(request: Request):
    data = await request.json()
    print("Threat received:", data)
    return{"status": "receieved"}