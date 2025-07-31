# common/login.py
import configparser
import pyotp
from kiteconnect import KiteConnect
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import logging
import ctypes
import os
from datetime import datetime, timedelta
from Connect import XTSConnect
from Exception import XTSTokenException, XTSDataException, XTSInputException

# Configure logging to a file
logging.basicConfig(
    filename='login_daemon.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def show_popup(title, message):
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)

# Load config from project root
# config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.ini")
config = configparser.ConfigParser()
config.read('config.ini')
Z = config["ZERODHA"]
x = config["XTS"]

# Global instance
kite = None

def zerodha_login():
    global kite 
    try:
        with open("access_token.txt") as f:
            access_token = f.read().strip()
            kite = KiteConnect(api_key=Z["API_KEY"])
            kite.set_access_token(access_token)
            # kite.set_session_expiry_hook(zerodha_login)
            kite.profile()
            logging.info("Access token valid. Login restored.")
            return kite
    except Exception:
        logging.info('Access token invalid. Re-logging in...')
    try:
        options = Options()
        # options.add_argument("--headless=new")
        driver = webdriver.Edge(options=options)

        kite = KiteConnect(api_key=Z["API_KEY"])
        kite.set_session_expiry_hook(zerodha_login)

        driver.get(kite.login_url())
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "userid"))).send_keys(Z["USER_ID"])
        driver.find_element(By.ID, "password").send_keys(Z["PASSWORD"])
        driver.find_element(By.XPATH, "//button[@type='submit']").click()

        totp_field = WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "userid"))
        )
        totp = str(pyotp.TOTP(Z["TOTP_SECRET"]).now())
        try:
            totp_field.clear()
            totp_field.send_keys(totp)
        except Exception:
            driver.execute_script("arguments[0].value = arguments[1];", totp_field, totp)
        time.sleep(2)
        WebDriverWait(driver, 15).until(EC.url_contains("request_token="))
        request_token = driver.current_url.split("request_token=")[1].split("&")[0]
        driver.quit()
        data = kite.generate_session(request_token, api_secret=Z["API_SECRET"])
        with open("access_token.txt", "w") as f:
            f.write(data["access_token"])
        kite.set_access_token(data["access_token"])
        logging.info("Login successful")
        return kite

    except Exception as e:
        if 'driver' in locals():
            driver.quit()
        logging.error(f"Login failed: {e}")
        show_popup("KiteConnect", "Login failed")
        raise

def login_xts():
    try:
        xts = XTSConnect(
            apiKey=x["API_KEY"].strip(),
            secretKey=x["API_SECRET"].replace("'","").strip(),
            source=x["source"].strip()
        )
        xts.interactive_login()
        return xts
    except Exception as e:
        logging.error(f"XTS login error: {str(e)}")
        raise

xts = login_xts()
kite = zerodha_login()