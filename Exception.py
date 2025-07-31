import requests
import json
from requests import exceptions
from requests.exceptions import HTTPError
from requests import ConnectTimeout, HTTPError, Timeout, ConnectionError

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
                Here we have declared all the exception and responses
    If there is any exception occurred we have this code to convey the messages
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""


class XTSException(Exception):
    """
    Base exception class representing a XTS client exception.

    Every specific XTS client exception is a subclass of this
    and  exposes two instance variables `.code` (HTTP error code)
    and `.message` (error text).
    """

    def __init__(self, message, code=500):
        """Initialize the exception."""
        super(XTSException, self).__init__(message)# Add these imports at the top of login.py
        import time
        from Connect import XTSConnect
        from Exception import XTSTokenException, XTSDataException, XTSInputException
        
        # Add these global variables
        XTS_MAX_RETRIES = 3
        XTS_RETRY_DELAY = 5  # seconds
        xts = None
        xts_last_login = 0
        XTS_LOGIN_EXPIRY = 60 * 60 * 12  # 12 hours
        
        def xts_relogin():
            """Re-login to XTS API and update the global instance"""
            global xts, xts_last_login
            try:
                logging.info("Attempting XTS re-login...")
                xts = XTSConnect(
                    api_key=x["API_KEY"],
                    secret_key=x["API_SECRET"],
                    source=x["source"]
                )
                login_response = xts.interactive_login()
                if login_response.get('type') == 'success':
                    xts_last_login = time.time()
                    logging.info("XTS re-login successful")
                    return True
                else:
                    logging.error(f"XTS re-login failed: {login_response.get('description')}")
                    return False
            except Exception as e:
                logging.error(f"XTS re-login error: {str(e)}")
                return False
        
        def xts_request(func, *args, **kwargs):
            """Wrapper function to handle XTS API requests with automatic reconnection"""
            global xts, xts_last_login
            
            # Check if we need to re-login
            if (not xts or not xts.token or 
                (time.time() - xts_last_login) > XTS_LOGIN_EXPIRY):
                if not xts_relogin():
                    raise Exception("XTS login required but re-login failed")
            
            # Try the request with retries
            for attempt in range(XTS_MAX_RETRIES):
                try:
                    return func(*args, **kwargs)
                except XTSTokenException:
                    logging.warning("XTS token expired, attempting to re-login...")
                    if not xts_relogin():
                        raise Exception("XTS re-login failed after token expiry")
                    if attempt == XTS_MAX_RETRIES - 1:
                        raise
                except (XTSDataException, XTSInputException) as e:
                    logging.error(f"XTS API error: {str(e)}")
                    raise
                except Exception as e:
                    logging.error(f"XTS request failed (attempt {attempt + 1}/{XTS_MAX_RETRIES}): {str(e)}")
                    if attempt == XTS_MAX_RETRIES - 1:
                        raise
                    time.sleep(XTS_RETRY_DELAY)
            
            raise Exception("Max retries exceeded for XTS request")
        
        def xts_login():
            """Initial XTS login"""
            global xts, xts_last_login
            try:
                if not xts or not xts.token or (time.time() - xts_last_login) > XTS_LOGIN_EXPIRY:
                    logging.info("Performing initial XTS login...")
                    if not xts_relogin():
                        raise Exception("Initial XTS login failed")
                return xts
            except Exception as e:
                logging.error(f"XTS login error: {str(e)}")
                raise
        
        # Update the login() function to include XTS login
        def login():
            global kite, xts
            try:
                # Existing Kite login logic
                with open("access_token.txt") as f:
                    access_token = f.read().strip()
                    kite = KiteConnect(api_key=Z["API_KEY"])
                    kite.set_access_token(access_token)
                    kite.set_session_expiry_hook(relogin)
                    kite.profile()
                    logging.info("Access token valid. Login restored.")
                    
                # Add XTS login
                xts = xts_login()
                    
                return kite, xts
                
            except Exception as e:
                logging.error(f"Login failed: {str(e)}")
                show_popup("Login Error", "Failed to login to one or more services")
                raise
        self.code = code


class XTSGeneralException(XTSException):
    """An unclassified, general error. Default code is 500."""

    def __init__(self, message, code=500):
        """Initialize the exception."""
        super(XTSGeneralException, self).__init__(message, code)


class XTSTokenException(XTSException):
    """Represents all token and authentication related errors. Default code is 400."""

    def __init__(self, message, code=400):
        """Initialize the exception."""
        super(XTSTokenException, self).__init__(message, code)


class XTSPermissionException(XTSException):
    """Represents permission denied exceptions for certain calls. Default code is 400."""

    def __init__(self, message, code=400):
        """Initialize the exception."""
        super(XTSPermissionException, self).__init__(message, code)


class XTSOrderException(XTSException):
    """Represents all order placement and manipulation errors. Default code is 500."""

    def __init__(self, message, code=400):
        """Initialize the exception."""
        super(XTSOrderException, self).__init__(message, code)


class XTSInputException(XTSException):
    """Represents user input errors such as missing and invalid parameters. Default code is 400."""

    def __init__(self, message, code=400):
        """Initialize the exception."""
        super(XTSInputException, self).__init__(message, code)


class XTSDataException(XTSException):
    """Represents a bad response from the backend Order Management System (OMS). Default code is 500."""

    def __init__(self, message, code=500):
        """Initialize the exception."""
        super(XTSDataException, self).__init__(message, code)


class XTSNetworkException(XTSException):
    """Represents a network issue between XTS and the backend Order Management System (OMS). Default code is 500."""

    def __init__(self, message, code=500):
        """Initialize the exception."""
        super(XTSNetworkException, self).__init__(message, code)
