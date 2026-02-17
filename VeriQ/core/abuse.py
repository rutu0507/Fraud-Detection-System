REQUESTS = {}

def rate_limited(ip):
    REQUESTS[ip] = REQUESTS.get(ip, 0) + 1
    return REQUESTS[ip] > 50
