import os
import random
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse
from app.core import base_models, helper_fun
from firebase_admin import auth
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from app.config import settings
from app.core import constants

load_dotenv()

router = APIRouter()

user_ref = settings.db.collection(constants.Database.FIREBASE_USER_DATABASE)

verification_code = {}

@router.post("/request_otp")
async def send_email(request: base_models.EmailRequest):
    email = request.email
    if not email or '@' not in email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address")

    try:
        user = auth.get_user_by_email(email)
        code = str(random.randint(1000, 9999))
        verification_code[email] = {
            'code': code,
            'expires_at': datetime.now() + timedelta(minutes=10)
        }
        helper_fun.send_verification_email(email=email, code=code)
        return JSONResponse(content={"message": f"Email sent to {email} and code is {code}", 'code': '200'},
                            status_code=200)
    except auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify_otp")
async def verify_otp(request: base_models.VerifyOTPRequest):
    email = request.email
    otp = request.otp
    if not email or not otp:
        raise HTTPException(status_code=400, detail="Email and OTP are required")

    if email in verification_code:
        stored_code = verification_code[email]['code']
        expires_at = verification_code[email]['expires_at']
        if datetime.now() > expires_at:
            del verification_code[email]
            raise HTTPException(status_code=400, detail="OTP has expired")
        if stored_code == otp:
            del verification_code[email]
            return JSONResponse(content={"message": "OTP verified successfully"}, status_code=200)
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP")
    else:
        raise HTTPException(status_code=400, detail="No OTP found for this email")


@router.post("/reset_password")
async def reset_password(request: base_models.ResetPasswordRequest):
    email = request.email
    new_password = request.new_password
    if not email or not new_password:
        raise HTTPException(status_code=400, detail="Email and new password are required")

    try:
        user = auth.get_user_by_email(email)
        auth.update_user(user.uid, password=new_password)
        return JSONResponse(content={"message": "Password reset successfully"}, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# Define the assetlinks.json content
assetlinks = [
  {
    "relation": [
      "delegate_permission/common.handle_all_urls",
      "delegate_permission/common.get_login_creds"
    ],
    "target": {
      "namespace": "android_app",
      "package_name": "com.hazrat.islam24",
      "sha256_cert_fingerprints": [
        "00:AE:C8:C3:1A:A0:A1:E6:EF:4D:26:01:2B:41:51:05:F8:CC:49:DA:F3:DD:CA:CD:07:BC:22:7C:61:27:FC:E6"
      ]
    }
  }
]

@router.get("/.well-known/assetlinks.json")
async def get_assetlinks():
    return JSONResponse(content=assetlinks)