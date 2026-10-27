
Install The Dependencies

python -m pip install fastapi uvicorn pydantic


Start the Server
Now, boot up the backend. Run this command:

python -m uvicorn main:app --reload


See it in action
Leave that black cmd window open. If you close it, you kill the server.

Open your web browser.

http://127.0.0.1:8000




http://103.45.67.89/secure/login/verify/auth/account-update.php?user=admin@target.xyz