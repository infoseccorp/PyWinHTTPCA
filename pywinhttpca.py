import sys
import ctypes
import win32crypt
import win32cryptcon
from ctypes import wintypes
from urllib.parse import urlparse, parse_qs

# Load the WinHTTP library
winhttp = ctypes.WinDLL('winhttp.dll')

# Define constants
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_FLAG_SECURE = 0x00800000
WINHTTP_OPTION_CLIENT_CERT_CONTEXT = 47
INTERNET_DEFAULT_HTTP_PORT = 80
INTERNET_DEFAULT_HTTPS_PORT = 443

# Define data structures
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_ulong),
                ("dwHighDateTime", ctypes.c_ulong)]

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [("wYear", ctypes.c_ushort),
                ("wMonth", ctypes.c_ushort),
                ("wDayOfWeek", ctypes.c_ushort),
                ("wDay", ctypes.c_ushort),
                ("wHour", ctypes.c_ushort),
                ("wMinute", ctypes.c_ushort),
                ("wSecond", ctypes.c_ushort),
                ("wMilliseconds", ctypes.c_ushort)]
                
class CRYPT_HASH_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(wintypes.BYTE))
    ]

class CERT_NAME_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(wintypes.BYTE))
    ]

class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('dwCertEncodingType', wintypes.DWORD),
        ('pbCertEncoded', ctypes.POINTER(wintypes.BYTE)),
        ('cbCertEncoded', wintypes.DWORD),
        ('pCertInfo', ctypes.c_void_p),
        ('hCertStore', ctypes.c_void_p)
    ]

# Set argument and return types for WinHTTP functions
winhttp.WinHttpOpen.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
winhttp.WinHttpOpen.restype = ctypes.c_void_p

winhttp.WinHttpConnect.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ushort, ctypes.c_void_p]
winhttp.WinHttpConnect.restype = ctypes.c_void_p

winhttp.WinHttpOpenRequest.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong]
winhttp.WinHttpOpenRequest.restype = ctypes.c_void_p

winhttp.WinHttpSendRequest.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
winhttp.WinHttpSendRequest.restype = ctypes.c_bool

winhttp.WinHttpReceiveResponse.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
winhttp.WinHttpReceiveResponse.restype = ctypes.c_bool

winhttp.WinHttpQueryDataAvailable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
winhttp.WinHttpQueryDataAvailable.restype = ctypes.c_bool

winhttp.WinHttpReadData.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
winhttp.WinHttpReadData.restype = ctypes.c_bool

winhttp.WinHttpCloseHandle.argtypes = [ctypes.c_void_p]
winhttp.WinHttpCloseHandle.restype = ctypes.c_bool

winhttp.WinHttpSetOption.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
winhttp.WinHttpSetOption.restype = ctypes.c_bool


def get_certificate_context(store_name="MY", system_store=win32cryptcon.CERT_SYSTEM_STORE_CURRENT_USER, issuer="", serial="", filename=""):

    with open(filename, 'rb') as f:
        cert_data = f.read()
  
    try:
        store = win32crypt.CertOpenStore(
            win32cryptcon.CERT_STORE_PROV_SYSTEM,
            0,
            None,
            system_store,
            store_name
        )
        if not store:
            raise Exception("Failed to open certificate store.")

        found_cert_context = None
        cert_context = None        
        cert_context = store.CertEnumCertificatesInStore() #returns a list of cert contexts
        for cert_info in cert_context:                                   
            if cert_info.CertEncoded == cert_data:                
                found_cert_context = cert_info
            else:
                cert_info.CertFreeCertificateContext()
            
        return found_cert_context
    
    except Exception as e:
         print(f"An error occurred: {e}")
         return None


def free_cert_context(cert_context):
    cert_context.CertFreeCertificateContext()
    

def send_http_request(url, cert_context):
    # Open a WinHTTP session
    session = winhttp.WinHttpOpen('Python WinHTTP Client', WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, None, None, 0)
    if not session:
        print(f"Error opening session: {ctypes.get_last_error()}")
        return

    try:
        request = None
        connect = None
        parsed_url = urlparse(url)        
        # Connect to the server
        if parsed_url.scheme != "https":
            print("URL is not an HTTPS URL")
            return
            
        host = parsed_url.hostname
        port = parsed_url.port
        if port == None:
            port = 443
        connect = winhttp.WinHttpConnect(session, host, port, 0)
        if not connect:
            print(f"Error connecting to server: {ctypes.get_last_error()}")
            return

        # Open an HTTP request        
        request = winhttp.WinHttpOpenRequest(connect, 'GET',  parsed_url.path, None, None, None, WINHTTP_FLAG_SECURE) 
        if not request:
            print(f"Error opening request: {ctypes.get_last_error()}")
            return
        
        void_ptr = ctypes.c_void_p(cert_context.HANDLE)        
        winhttp.WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, void_ptr, ctypes.sizeof(CERT_CONTEXT)) 
        
        # Send the request
        if not winhttp.WinHttpSendRequest(request, None, 0, None, 0, 0, 0):
            print(f"Error sending request: {ctypes.get_last_error()}")
            return
      
        # Receive the response
        if not winhttp.WinHttpReceiveResponse(request, None):
            print(f"Error receiving response: {ctypes.get_last_error()}")
            return

        wholebuffer = ""
        while(True):
            # Read the response data
            data_available = ctypes.c_ulong(0)
            if not winhttp.WinHttpQueryDataAvailable(request, ctypes.byref(data_available)):
                break
                
            if data_available.value == 0:
                break
                
            buffer_size = data_available.value        
            buffer = ctypes.create_string_buffer(buffer_size)
            bytes_read = ctypes.c_ulong(0)
            if not winhttp.WinHttpReadData(request, buffer, buffer_size, ctypes.byref(bytes_read)):
                break
                
            wholebuffer += buffer.value.decode('utf-8')

        # Print the response
        print(wholebuffer)

    finally:
        # Close handles
        if request:
            winhttp.WinHttpCloseHandle(request)
        if connect:
            winhttp.WinHttpCloseHandle(connect)
        if session:
            winhttp.WinHttpCloseHandle(session)



def main(arg1, arg2):
   
    my_cert_context = get_certificate_context(filename=arg2)
    if my_cert_context == None:
        print("Error, failed to find certificate in CAPI")
        return
        
    send_http_request(arg1, my_cert_context)
    
    #free the allocated certificate context
    my_cert_context.CertFreeCertificateContext()
    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pywinhttpca.py url der_cer")
    else:
        main(sys.argv[1], sys.argv[2])



