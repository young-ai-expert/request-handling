import firebase_admin
from flask import Flask,request,jsonify
from flask_cors import CORS
from firebase_admin import auth, credentials, firestore
import os
from dotenv import load_dotenv
import json # Import json to read the service account file

# Load environment variables from .env file
load_dotenv()

service_account_path =  os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

try:
    if not firebase_admin._apps: # Check if app is already initialized
        if service_account_path and os.path.exists(service_account_path):
            cred = credentials.Certificate(service_account_path)
            # Read the project ID from the service account key file
            with open(service_account_path) as f:
                service_account_info = json.load(f)
                project_id = service_account_info.get('project_id')

            if project_id:
                firebase_admin.initialize_app(cred, {'projectId': project_id})
                print(f"Firebase Admin SDK initialized using credentials from: {service_account_path} with project ID: {project_id}")
            else:
                # Fallback if project_id is not in the service account file (less common)
                 firebase_admin.initialize_app(cred)
                 print(f"Firebase Admin SDK initialized using credentials from: {service_account_path} (project ID not explicitly set)")

        else:
            # This part will be reached if FIREBASE_SERVICE_ACCOUNT_PATH is not set or file not found
            # It relies on Application Default Credentials or GOOGLE_CLOUD_PROJECT
            firebase_admin.initialize_app()
            print("Firebase Admin SDK initialized without explicit service account path (relying on default credentials/environment).")

except ValueError as e:
    print(f"Firebase initialization error (might be already initialized or bad credentials): {e}")
    if not service_account_path:
        print("ERROR: FIREBASE_SERVICE_ACCOUNT_PATH not found in .env or GOOGLE_APPLICATION_CREDENTIALS not set.")
        print("Please ensure your .env file is correctly configured and the path to your service account key is correct.")
    elif not os.path.exists(service_account_path):
        print(f"ERROR: Service account file not found at the specified path: {service_account_path}")
        print("Please verify the path in your .env file.")
except Exception as e:
    print(f"An unexpected error occurred during Firebase initialization: {e}")

# Get Firestore client (only if Firebase app was successfully initialized)
try:
    db = firestore.client()
    print("Firestore client initialized.")
except Exception as e:
    print(f"Failed to initialize Firestore client: {e}")
    db = None # Set db to None if initialization failed


app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for your frontend

def authenticate_token(f):
    def decorated_function(*args, **kwargs):
        if not firebase_admin._apps:
            print("Firebase Admin SDK not initialized. Cannot authenticate token.")
            return jsonify({"error": "Server configuration error: Firebase not ready"}), 500

        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            print("Authentication failed: Missing or invalid Authorization header.")
            return jsonify({"error": "Unauthorized: Missing or malformed token"}), 401

        token = auth_header.split(" ")[1]  # Extract JWT token

        try:
            # Verify the Firebase ID token. This ensures the token is valid,
            # not expired, and issued by Firebase for your project.
            decoded_token = auth.verify_id_token(token)
            # Attach the decoded token (which contains the user's uid) to the request
            request.uid = decoded_token['uid']
            print(f"Token verified for UID: {request.uid}")
            return f(*args, **kwargs) # Proceed to the decorated function
        except auth.InvalidIdTokenError:
            print("Authentication failed: Invalid Firebase ID token.")
            return jsonify({"error": "Unauthorized: Invalid token"}), 401
        except Exception as e:
            print(f"Authentication failed: An unexpected error occurred: {e}")
            return jsonify({"error": f"Unauthorized: Internal server error {e}"}), 500
    decorated_function.__name__ = f.__name__ # Preserve original function name for Flask
    return decorated_function


@app.route('/api/username', methods=['GET'])
@authenticate_token
def get_username():
    try:
        # Retrieve user details from Firebase Auth using the UID from the decoded token
        user = auth.get_user(request.uid)
        username = user.display_name if user.display_name else "User"
        print(f"Returning username for UID {request.uid}: {username}")
        return jsonify({"username": username})
    except auth.UserNotFoundError:
        print(f"Error: User with UID {request.uid} not found in Firebase Auth.")
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"Error fetching user data: {e}")
        return jsonify({"error": "Could not retrieve username"}), 500

@app.route('/api/user_profile', methods=['GET'])
@authenticate_token
def get_user_profile():
    if db is None:
        return jsonify({"error": "Firestore not initialized"}), 500

    try:
        user_id = request.uid
        doc_ref = db.collection('users').document(user_id)
        doc = doc_ref.get()

        if doc.exists:
            profile_data = doc.to_dict()
            print(f"Fetched profile for UID {user_id}: {profile_data}")
            return jsonify(profile_data)
        else:
            print(f"No profile found for UID {user_id}. Returning default.")
            # Optionally, create a default profile or return a specific message
            return jsonify({"message": "Profile not found for this user, please create one."}), 404
    except Exception as e:
        print(f"Error fetching user profile from Firestore: {e}")
        return jsonify({"error": "Failed to retrieve user profile"}), 500


@app.route('/api/update_profile', methods=['POST'])
@authenticate_token
def update_user_profile():
    """
    Example protected endpoint to update user-specific data in Firestore.
    Expects JSON body with profile fields.
    """
    if db is None:
        return jsonify({"error": "Firestore not initialized"}), 500

    try:
        user_id = request.uid
        data = request.json
        if not data:
            return jsonify({"error": "Request must contain JSON data"}), 400

        doc_ref = db.collection('users').document(user_id)
        doc_ref.set(data, merge=True) # Use merge=True to update fields without overwriting the whole document
        print(f"Updated profile for UID {user_id} with data: {data}")
        return jsonify({"message": "Profile updated successfully"})
    except Exception as e:
        print(f"Error updating user profile in Firestore: {e}")
        return jsonify({"error": "Failed to update user profile"}), 500


@app.route('/')
def home():
    return "Flask Backend for Flutter App is running!"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
