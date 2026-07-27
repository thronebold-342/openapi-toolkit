import json

import sys


#Breaking
#---------
#Removed endpoint
#Removed method
#Required parameter added
#Response field removed

#Non-breaking
#------------
#New endpoint
#New method
#Optional parameter added
#Optional response property

#Warnings
#--------
#Description changed
#Tag changed
#Server URL changed
#Summary changed

breaking_changes = []
non_breaking_changes = []
warnings = []

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "options",
    "head",
    "trace"
}


try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False




def load_spec(filename):
    """Load an OpenAPI spec from a JSON or YAML file, with error handling."""

    try:
        with open(filename, "r") as f:
            content = f.read()

    except FileNotFoundError:
        print(f"Error: '{filename}' not found. Check the path and try again.")
        sys.exit(1)

    except PermissionError:
        print(f"Error: no permission to read '{filename}'.")
        sys.exit(1)

    spec, json_error, yaml_error = None, None, None

    # Try JSON first — gives precise line/col errors when the file really is JSON
    try:
        spec = json.loads(content)
    except json.JSONDecodeError as e:
        json_error = e

    # Fall back to YAML — this also transparently handles .yaml/.yml files,
    # since valid JSON happens to also be valid YAML
    if json_error is not None:
        if not YAML_AVAILABLE:
            print(f"Error: '{filename}' isn't valid JSON, and PyYAML isn't installed to try YAML.")
            print("Install it with: pip install pyyaml")
            sys.exit(1)

        try:
            spec = yaml.safe_load(content)
        except yaml.YAMLError as e:
            yaml_error = e

    if json_error is not None and yaml_error is not None:
        print(f"Error: '{filename}' could not be parsed as JSON or YAML.")
        print(f"  JSON error: {json_error}")
        print(f"  YAML error: {yaml_error}")
        sys.exit(1)

    if spec is None:
        print(f"Error: '{filename}' is empty or parsed to nothing.")
        sys.exit(1)

    if not isinstance(spec, dict):
        print(f"Error: '{filename}' does not contain an object at the top level.")
        sys.exit(1)

    if "paths" not in spec:
        print(f"Error: '{filename}' has no 'paths' key — doesn't look like an OpenAPI spec.")
        sys.exit(1)

    return spec



def compare_specs(old_file, new_file): #loads both files innto old_spec and new_spec // camparison functions are also ran here

    old_spec = load_spec(old_file)
    new_spec = load_spec(new_file)

    print("Old spec loaded.")
    print("New spec loaded.")
    
    old_spec, new_spec = resolve_refs(old_spec, new_spec) # ← capture + reassign

    # Comparison functions will go here
    compare_paths(old_spec, new_spec) #checked
    compare_parameters(old_spec, new_spec) #checked
    compare_request_bodies(old_spec, new_spec) #checked
    compare_response_bodies(old_spec, new_spec) #checked
    compare_components(old_spec, new_spec) #checked
    
    
    compare_security(old_spec, new_spec)#arnt running
    
    compare_servers(old_spec, new_spec) #arnt running
    compare_tags(old_spec, new_spec) #arnt running

    

def compare_paths(old_spec, new_spec):

    print("Comparing paths...\n")


    # Convert paths into sets
    old_paths = set(old_spec.get("paths", {}).keys())
    new_paths = set(new_spec.get("paths", {}).keys())


    # Find removed and added paths
    removed_paths = old_paths - new_paths
    added_paths = new_paths - old_paths


    # Removed endpoints
    for path in removed_paths:
        print(f"Removed path: {path}")

        breaking_changes.append({
            "severity": "High",
            "rule": "REMOVED_ENDPOINT",
            "message": f"{path} endpoint removed"
        })


    # Added endpoints
    for path in added_paths:
        print(f"New path: {path}")

        non_breaking_changes.append({
            "severity": "Low",
            "rule": "ADDED_ENDPOINT",
            "message": f"{path} endpoint added"
        })


    # Compare paths that exist in both specifications
    common_paths = old_paths & new_paths


    for path in common_paths:

        old_methods = [
            method
            for method in old_spec["paths"][path].keys()
            if method.lower() in HTTP_METHODS
        ]

        new_methods = [
            method
            for method in new_spec["paths"][path].keys()
            if method.lower() in HTTP_METHODS
        ]


        # Convert to sets for comparison
        old_methods = set(old_methods)
        new_methods = set(new_methods)


        removed_methods = old_methods - new_methods
        added_methods = new_methods - old_methods


        # Removed methods
        for method in removed_methods:
            print(f"Removed method: {method.upper()} {path}")

            breaking_changes.append({
                "severity": "High",
                "rule": "REMOVED_METHOD",
                "message": f"{method.upper()} {path} removed"
            })


        # Added methods
        for method in added_methods:
            print(f"New method: {method.upper()} {path}")

            non_breaking_changes.append({
                "severity": "Low",
                "rule": "ADDED_METHOD",
                "message": f"{method.upper()} {path} added"
            })


        print(f"Path: {path}")
        print(f"Old methods: {old_methods}")
        print(f"New methods: {new_methods}")
        print()

     #this method has been completed and closed
def compare_parameters(old_spec, new_spec):

    print("Comparing parameters...\n")

    # Get paths from both specifications
    old_paths = set(old_spec.get("paths", {}).keys()) #old_spec.get("paths", {}) - gives value stored in "paths", if doesnt exist, empty {} dict is given
    #.keys() means - I only care about the endpoint names, not their details."
    #set()- converts something into set()-  1. It cannot contain duplicates. 2.It is designed for fast checking: "does this exist?"
    new_paths = set(new_spec.get("paths", {}).keys())

    # Only compare paths that exist in both versions
    common_paths = old_paths & new_paths #get "Which items exist in BOTH sets?" and put them into common paths - "intersections"
    #the reason we need common paths is because we need to get the HTTP

    for path in common_paths: #common paths involve keys right under path e.g "/users" assuming it is in both specs

        old_methods = {
            method
            for method in old_spec["paths"][path] 
            if method.lower() in HTTP_METHODS
        }

        new_methods = {
            method
            for method in new_spec["paths"][path]
            if method.lower() in HTTP_METHODS
        }  #[path] here is keys like "/users" right under the first "path"


        # Only compare methods that exist in both versions
        common_methods = old_methods & new_methods 


        for method in common_methods: 

            old_operation = old_spec["paths"][path][method] 
            new_operation = new_spec["paths"][path][method] 


            # Get parameters, empty list if none exist
            old_parameters = old_operation.get("parameters", []) 
            new_parameters = new_operation.get("parameters", [])


            # Create lookup dictionaries using (name, location)
            old_params = {}
            for param in old_parameters:
                old_params[(param["name"], param["in"])] = param #creates a look up dict using the param "name" and "in" and stores in old_params


            new_params = {}
            for param in new_parameters:
                new_params[(param["name"], param["in"])] = param


            # Check if new parameters were added
            for key, parameter in new_params.items(): #returns both key and item in dict in form , key, parameter, key = name and in, parameter = actual parameter .keys() - like below
                
                #key = ("id", "query")

                #parameter = {
                  #  "name": "id",
                  #  "in": "query",
                  #  "required": True
                  #  }
                

                if key not in old_params:

                    # Required parameter = breaking
                    if parameter.get("required", False): #"Try to get the value stored under this key. If the key doesn't exist, return the default value instead."
                    #so if the value is false it returns false, and if the value is true is returns true but if its empty it returns false

                        breaking_changes.append({
                            "severity": "High",
                            "rule": "REQUIRED_PARAMETER_ADDED",
                            "message": f"{method.upper()} {path} added required parameter '{parameter['name']}'"
                        })

                    # Optional parameter = non-breaking
                    else:

                        non_breaking_changes.append({
                            "severity": "Low",
                            "rule": "OPTIONAL_PARAMETER_ADDED",
                            "message": f"{method.upper()} {path} added optional parameter '{parameter['name']}'"
                        })
                        
            # Check if parameters were removed or became required
            for key, parameter in old_params.items():

                if key not in new_params:

                    # Removed parameter = breaking
                    breaking_changes.append({
                        "severity": "High",
                        "rule": "PARAMETER_REMOVED",
                        "message": f"{method.upper()} {path} removed parameter '{parameter['name']}'"
                    })

                else:

                    # Parameter still exists — check if it became required
                    old_required = parameter.get("required", False)
                    new_required = new_params[key].get("required", False)

                    if old_required == False and new_required == True:

                        breaking_changes.append({
                            "severity": "High",
                            "rule": "PARAMETER_NOW_REQUIRED",
                            "message": f"{method.upper()} {path} parameter '{parameter['name']}' changed from optional to required"
                        })   
    
#this method has been completed and closed

def compare_request_bodies(old_spec, new_spec):

    print("Comparing request bodies...\n")

    old_paths = set(old_spec.get("paths", {}).keys())
    new_paths = set(new_spec.get("paths", {}).keys())

    common_paths = old_paths & new_paths


    for path in common_paths:

        old_methods = {
            method
            for method in old_spec["paths"][path]
            if method.lower() in HTTP_METHODS
        }

        new_methods = {
            method
            for method in new_spec["paths"][path]
            if method.lower() in HTTP_METHODS
        }


        common_methods = old_methods & new_methods


        for method in common_methods:

            old_operation = old_spec["paths"][path][method]
            new_operation = new_spec["paths"][path][method]


            old_body = old_operation.get("requestBody")
            new_body = new_operation.get("requestBody")


            # Request body removed
            if old_body and not new_body:

                breaking_changes.append({
                    "severity": "High",
                    "rule": "REQUEST_BODY_REMOVED",
                    "message": f"{method.upper()} {path} request body removed"
                })


            # Request body added
            if new_body and not old_body:

                non_breaking_changes.append({
                    "severity": "Low",
                    "rule": "REQUEST_BODY_ADDED",
                    "message": f"{method.upper()} {path} request body added"
                })


            # If both exist compare fields
            if old_body and new_body:

                old_schema = (
                    old_body
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )


                new_schema = (
                    new_body
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )


                old_fields = get_properties(old_schema)
                new_fields = get_properties(new_schema)


                # New fields
                for field in new_fields:

                    if field not in old_fields:

                        if field in new_schema.get("required", []):

                            breaking_changes.append({
                                "severity": "High",
                                "rule": "REQUIRED_REQUEST_FIELD_ADDED",
                                "message": f"{method.upper()} {path} required field '{field}' added"
                            })

                        else:

                            non_breaking_changes.append({
                                "severity": "Low",
                                "rule": "OPTIONAL_REQUEST_FIELD_ADDED",
                                "message": f"{method.upper()} {path} optional field '{field}' added"
                            })


                # Removed fields
                for field in old_fields:

                    if field not in new_fields:

                        breaking_changes.append({
                            "severity": "High",
                            "rule": "REQUEST_FIELD_REMOVED",
                            "message": f"{method.upper()} {path} field '{field}' removed"
                        })

    

        
        
    
    


    
    
    
    
def compare_response_bodies(old_spec, new_spec):#response bodies

    print("Comparing response bodies...\n")

    old_paths = set(old_spec.get("paths", {}).keys())
    new_paths = set(new_spec.get("paths", {}).keys())

    common_paths = old_paths & new_paths

    for path in common_paths:

        old_methods = {
            method
            for method in old_spec["paths"][path]
            if method.lower() in HTTP_METHODS
        }

        new_methods = {
            method
            for method in new_spec["paths"][path]
            if method.lower() in HTTP_METHODS
        }

        common_methods = old_methods & new_methods

        for method in common_methods:

            old_operation = old_spec["paths"][path][method]
            new_operation = new_spec["paths"][path][method]

            old_responses = old_operation.get("responses", {})
            new_responses = new_operation.get("responses", {})

            common_status_codes = set(old_responses.keys()) & set(new_responses.keys())

            for status_code in common_status_codes:

                old_response = old_responses[status_code]
                new_response = new_responses[status_code]

                old_schema = (
                    old_response
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )

                new_schema = (
                    new_response
                    .get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                )

                old_fields = get_properties(old_schema)
                new_fields = get_properties(new_schema)

                # Removed response field = breaking (client may depend on reading it)
                for field in old_fields:
                    if field not in new_fields:
                        breaking_changes.append({
                            "severity": "High",
                            "rule": "RESPONSE_FIELD_REMOVED",
                            "message": f"{method.upper()} {path} {status_code} response field '{field}' removed"
                        })

                # Added response field = non-breaking
                for field in new_fields:
                    if field not in old_fields:
                        non_breaking_changes.append({
                            "severity": "Low",
                            "rule": "RESPONSE_FIELD_ADDED",
                            "message": f"{method.upper()} {path} {status_code} response field '{field}' added"
                        })
    
    
    
def get_properties(schema): #for compare_response_bodies() and compare_request_bodies()
    """Given a resolved schema, return its properties dict —
    unwrapping one level if the schema is an array of objects."""

    if schema.get("type") == "array":
        schema = schema.get("items", {})

    return schema.get("properties", {})#for compare_response_properties method for compare_response_bodies()
 #g
    
    
def compare_components(old_spec, new_spec): #componenets
    print("Comparing components...\n")

    old_schemas = old_spec.get("components", {}).get("schemas", {})
    new_schemas = new_spec.get("components", {}).get("schemas", {})

    common_schemas = set(old_schemas.keys()) & set(new_schemas.keys())

    for schema_name in common_schemas:

        old_fields = old_schemas[schema_name].get("properties", {})
        new_fields = new_schemas[schema_name].get("properties", {})

        # Removed field = breaking
        for field in old_fields:
            if field not in new_fields:
                breaking_changes.append({
                    "severity": "High",
                    "rule": "COMPONENT_FIELD_REMOVED",
                    "message": f"Schema '{schema_name}' field '{field}' removed"
                })

        # Added field = non-breaking
        for field in new_fields:
            if field not in old_fields:
                non_breaking_changes.append({
                    "severity": "Low",
                    "rule": "COMPONENT_FIELD_ADDED",
                    "message": f"Schema '{schema_name}' field '{field}' added"
                })


                
                
def resolve_refs(old_spec, new_spec):
    """Replace every $ref in both specs with its resolved definition,
    so downstream comparison functions never have to deal with $ref."""

    def resolve(node, spec, seen):

        if isinstance(node, dict):

            if "$ref" in node:
                ref = node["$ref"]

                if ref in seen:
                    return {}  # circular reference guard

                seen = seen | {ref}

                # "#/components/schemas/User" -> ["components", "schemas", "User"]
                parts = ref.lstrip("#/").split("/")
                target = spec
                for part in parts:
                    target = target.get(part, {})

                return resolve(target, spec, seen)

            return {
                key: resolve(value, spec, seen)
                for key, value in node.items()
            }

        if isinstance(node, list):
            return [resolve(item, spec, seen) for item in node]

        return node

    resolved_old = resolve(old_spec, old_spec, set())
    resolved_new = resolve(new_spec, new_spec, set())

    return resolved_old, resolved_new
                
                
                
                
                
def compare_security(old_spec, new_spec): #security
    pass
def compare_servers(old_spec, new_spec): #servers
    pass 
def compare_tags(old_spec, new_spec): #tags
    pass




if __name__ == "__main__":
    compare_specs("old_spec.yaml", "new_spec.yaml")



print()
print("----REPORT-----")
for changes in breaking_changes:
    print(f"{changes["severity"]} - {changes["rule"]} - {changes["message"]}")
print()

for changes in non_breaking_changes:
    print(f"{changes["severity"]} - {changes["rule"]} - {changes["message"]}")
    

    
#Artitechture

#└── compare_tags()
    
    