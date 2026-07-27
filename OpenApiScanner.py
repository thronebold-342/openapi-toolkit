
import json
import re

findings = []
highThreats = []
mediumThreats = []
lowThreats = []


DEBUG = False

with open("OpenApiJsonVaulnerabilities.json") as f:
    old_spec = json.load(f)

#with open("json2.json") as f:
    #new_spec = json.load(f)

old_paths = old_spec.get("paths", {}) #opens the "paths" drawer and hands you 





def explore(data, depth=0):
    indent = "  " * depth
    
    if isinstance(data, dict): #isinstance(data, type) in this case .. is data a dictionary
        for key, value in data.items():
            
            # RULE 9 — sensitive schema keys
            check_sensitive_schema_key(key, value)
            
            
            
            if key == "description": #rule 13
                check_sensitive_description(value)
            
            if DEBUG:
                print(f"{indent}KEY: {key}")
            explore(value, depth + 1)         

    elif isinstance(data, list):
        for i, item in enumerate(data):
            
            if DEBUG:
                print(f"{indent}[{i}]")
            explore(item, depth + 1)

    else:
        if DEBUG:
            print(f"{indent}VALUE: {data}")
        
        check_secrets(data) #run rule 1
        

    
    

#################===========RULES===========#######################
#################===========RULES===========#######################

#RULE 1. Hardcoded secrets & 13. sensetive words in description

import re

SECRET_PATTERNS = [ #rule 1
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[a-zA-Z0-9]{36}",
    r"sk-[a-zA-Z0-9]{20,}",
    r"(?i)password\s*[:=]\s*\S+",
    r"(?i)secret\s*[:=]\s*\S+"
]

def check_secrets(value): #rule 1
    if not isinstance(value, str):
        return

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, value):
            #print(f"CRITICAL: Secret detected -> {value}")
            findings.append({
                "severity": "CRITICAL",
                "rule": "HARDCODED_SECRET",
                "message": f"Secret detected: {value} /R1"
            })

            
SENSETIVE_WORDS = [ #rule 13
    r"internal",
    r"debug",
    r"test",
    r"do not expose",
    r"private"
]
            
def check_sensitive_description(value): #RULE 13
    if not isinstance(value, str):
        return
    
    for word in SENSETIVE_WORDS:
        if word.lower() in value.lower():
            
            lowThreats.append({
                "severity": "LOW",
                "rule": "SENSITIVE_DESCRIPTION",
                "message": f"Sensitive wording found in description: {value} /R13"
            })
            
            break
        
        

#RULE 2, 3, 8, 10

SENSITIVE_PATHS = [ #RULE 2
    "/admin",
    "/internal",
    "/debug",
    "/root",
    "/superuser"
]

def check_sensitive_endpoint(path, operation): #RULE 2

    sensitive = any(
        keyword in path.lower()
        for keyword in SENSITIVE_PATHS
    )

    if sensitive and "security" not in operation:
        findings.append({
            "severity": "CRITICAL",
            "rule": "NO_AUTH",
            "message": f"Sensitive endpoint without auth: {path} R2"
        })

# HIGH RULES 3
#RULE 3 - no security field on any endpoint

def check_missing_security(path, operation):
    if "security" not in operation:
        highThreats.append({
            "severity": "HIGH",
            "rule": "MISSING_SECURITY",
            "message": f"No security field on endpoint: {path} /R3"
        })
        
    elif operation["security"] == []:
        highThreats.append({
            "severity": "HIGH",
            "rule": "EMPTY_SECURITY",
            "message": f"Empty security list on endpoint: {path} /R3"
        })
        

        
# RULE 8 - Medium Threats - POST or PUT with requestbody marked as False


def check_request_body_required(path, method, operation): #Rule 8

    if method.lower() not in ["post", "put"]:
        return

    request_body = operation.get("requestBody")

    if not request_body:
        return

    required = request_body.get("required")

    if required is False:
        mediumThreats.append({
            "severity": "MEDIUM",
            "rule": "REQUEST_BODY_NOT_REQUIRED",
            "message": f"{method.upper()} {path} has requestBody.required = false /R8"
        })
# RULE 10 -additionalProperties set to true on PUT or PATCH 

def check_aditional_properties_set_true(path, method, operation):
    if method.lower() not in ["put", "patch"]:
        return

    request_body = operation.get("requestBody")
    if not request_body:
        return

    content = request_body.get("content", {})
    json_media = content.get("application/json", {})
    schema = json_media.get("schema", {})

    additional_properties = schema.get("additionalProperties")

    if additional_properties is True:
        mediumThreats.append({ #mediumThreats
            "severity": "MEDIUM",
            "rule": "ADDITIONAL_PROPERTIES_TRUE",
            "message": f"{method.upper()} {path} allows unrestricted additionalProperties /R10"
        })


#Rule 4 

def check_insecure_servers(spec): #Rule 4 
    servers = spec.get("servers", [])

    for server in servers:
        if not isinstance(server, dict):
            continue

        url = server.get("url", "")

        if isinstance(url, str) and url.lower().startswith("http://"):
            highThreats.append({
                "severity": "HIGH",
                "rule": "INSECURE_SERVER_HTTP",
                "message": f"Server uses HTTP instead of HTTPS: {url} /R4"
            })
        
# Rule 5

def check_basic_auth(spec):
    security_schemes = (
        spec.get("components", {})
            .get("securitySchemes", {})
    )

    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue

        if scheme.get("scheme", "").lower() == "basic":
            highThreats.append({
                "severity": "HIGH",
                "rule": "BASIC_AUTH_USED",
                "message": f"Security scheme '{name}' uses Basic authentication. /R5"
            })
            
            
#rule 6

def check_api_key_in_query(spec):
    security_schemes = (
        spec.get("components", {})
            .get("securitySchemes", {})
    )

    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue

        if (
            scheme.get("type", "").lower() == "apikey"
            and scheme.get("in", "").lower() == "query"
        ):
            highThreats.append({
                "severity": "HIGH",
                "rule": "API_KEY_IN_QUERY",
                "message": f"Security scheme '{name}' passes API key in query parameters. /R6"
            })
    
#rule 7

def check_global_security(spec):
    security = spec.get("security")

    if security is None:
        mediumThreats.append({
            "severity": "MEDIUM",
            "rule": "NO_GLOBAL_SECURITY",
            "message": "No global security fallback defined at root level /R7"
        })
        
        
SENSITIVE_SCHEMA_KEYS = [ #for rule 9
    "password_hash",
    "passwordHash",
    "passwordPlaintext",
    "masterPassword",
    "adminPassword",
    "dbPassword",
    "ssn",
    "credit_card",
    "cvv",
    "dob",
    "secret",
    "private_key",
    "privateKey",
    "apiKey",
    "token",
    "accessToken",
    "refreshToken",
]

# Rule 9

def check_sensitive_schema_key(key, value):
    if key.lower() in SENSITIVE_SCHEMA_KEYS:
        mediumThreats.append({
            "severity": "MEDIUM",
            "rule": "SENSITIVE_SCHEMA_FIELD",
            "message": f"Sensitive field name detected: {key} /R9"
        })

    

# RULE 11
def check_empty_response_schema(path, method, operation):

    responses = operation.get("responses", {})

    for status_code, response in responses.items():

        content = response.get("content")

        if not content:
            lowThreats.append({
                "severity": "LOW",
                "rule": "EMPTY_RESPONSE_SCHEMA",
                "message": f"{method.upper()} {path} [{status_code}] has no response content/schema /R11"
            })
            continue

        # check if ANY schema exists inside content types
        has_schema = False

        for media_type, media_obj in content.items():
            if isinstance(media_obj, dict) and "schema" in media_obj:
                has_schema = True
                break

        if not has_schema:
            lowThreats.append({
                "severity": "LOW",
                "rule": "EMPTY_RESPONSE_SCHEMA",
                "message": f"{method.upper()} {path} [{status_code}] has content but no schema defined /R11"
            })
            
#RULE 12

def check_missing_servers_block(spec):

    if "servers" not in spec:
        lowThreats.append({
            "severity": "LOW",
            "rule": "MISSING_SERVERS_BLOCK",
            "message": "No servers block defined at root level /R12"
        })
        

explore(old_spec)

check_insecure_servers(old_spec) #RUN - RULE 4
check_basic_auth(old_spec) #RUN rule 5
check_api_key_in_query(old_spec) #RUN rule 6
check_global_security(old_spec) # RUN rule 7
check_missing_servers_block(old_spec) # RUN rule 12




for path, details in old_paths.items(): #RUN RULE 2,3, 8 and 10

    for method, operation in details.items():

        check_sensitive_endpoint(path, operation) #rule 2
        check_missing_security(path, operation) #rule 3
        check_request_body_required(path, method, operation) #rule 8
        check_aditional_properties_set_true(path, method, operation) #rule 10
        check_empty_response_schema(path, method, operation) #Rule 11
        


        
        
#PRINT SECURITY REPORT    
print("")

print("=======FINDINGS=======:")
print(" ")

#print(findings)


print("FINDINGS/critical")
for finding in findings:
    print(
        f"[{finding['severity']}] "
        f"[{finding['rule']}] "
        f"{finding['message']}"
    )
    
print("hIGH THREATS")
for highThreat in highThreats:
    print(
        f"[{highThreat['severity']}] "
        f"[{highThreat['rule']}] "
        f"{highThreat['message']}"
    )
    
    
print("LOW THREATS")
for lowThreat in lowThreats:
    print(
        f"[{lowThreat['severity']}] "
        f"[{lowThreat['rule']}] "
        f"{lowThreat['message']}"
    )

print("MEDIUM THREATS")
for mediumThreat in mediumThreats:
    print(
        f"[{mediumThreat['severity']}] "
        f"[{mediumThreat['rule']}] "
        f"{mediumThreat['message']}"
    )
    
    
    
    

    
    
    
#RULE 1 - DONE
#RULE 2 - DONE
#RULE 3 - DONE
#RULE 4 - DONE 
#RULE 5 - DONE
#RULE 6 -DONE
#RULE 7 - DONE
#RULE 8 - DONE
#RULE 9 - DONE
#RULE 10 - DONE
#RULE 11 - DONE
#RULE 12 - DONE
#RULE 13 - DONE
