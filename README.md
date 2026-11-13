# Endpoint Threat Detection - Log Analyzer

A Streamlit app for parsing uploaded endpoint/system logs, running heuristic detections, and correlating activity.

## Run locally

From the project directory in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m streamlit run app.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## Deploy publicly with Streamlit Community Cloud

1. Create an **empty** GitHub repository (do not initialize it with a README or other files).
2. From this project directory, push the project to that repository:

   ```powershell
   git init
   git add .
   git commit -m "Prepare log analyzer for deployment"
   git branch -M main
   git remote add origin https://github.com/<YOUR-USERNAME>/<YOUR-REPOSITORY>.git
   git push -u origin main
   ```

3. Sign in at [Streamlit Community Cloud](https://share.streamlit.io/) with GitHub and choose **Create app**.
4. Select your repository and `main` branch, set the app file path to `app.py`, then deploy.
5. Share the public URL shown in the app dashboard. Future pushes to the selected branch will trigger redeployment.

The dependencies are listed in the root-level `requirements.txt`, which Community Cloud installs during deployment.

## Data handling

The app has no authentication, so anyone with its public URL can access it and upload files. Uploaded logs are sent to
the host running the app. The app code does not save uploads to persistent storage, but do not use this public app for
sensitive, personal, or production logs. Use a private, access-controlled deployment for those.
