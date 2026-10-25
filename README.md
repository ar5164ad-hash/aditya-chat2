# Aditya Chat

## Run
1. Install Node.js (v16+).
2. Your photo is already set as the background (`public/background.png`); replace that file to change it.
3. `node server.js`
4. Open http://localhost:3000 (on a phone: http://<your-computer-IP>:3000 on the same Wi-Fi, then "Add to Home screen" to install).

## Flow
Welcome -> choose serial no. (max 5 digits, unique) -> enter name -> Home with dial-style search
-> tap a user -> profile page with text messaging.

A serial number, once taken, is reserved permanently for that user. Searching it shows the holder's name.
The "Aditya" watermark appears on the side of every page. Data is stored in `data.json`.

To let anyone download/use it from anywhere, deploy this folder to any Node host (Render, Railway, etc.).
