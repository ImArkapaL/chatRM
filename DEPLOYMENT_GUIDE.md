# chatRM - Real-time Chat Application

## Deployment Instructions for Back4App

### Prerequisites
- Back4App account (free tier available)
- Git installed
- Python 3.8+ (for local development)

### Step 1: Create Parse App on Back4App

1. Go to https://www.back4app.com
2. Sign up or log in
3. Click "Create new app"
4. Choose "Node.js" backend
5. Name your app "chatRM"
6. Click "Create"

### Step 2: Get Your Credentials

After creating the app, you'll see:
- **Application ID**: Copy this
- **Master Key**: Copy this
- **Server URL**: Note this (format: https://YOUR_APP_ID.b4a.io)

### Step 3: Configure Your Local Environment

Create a `.env` file in the root directory:

```
PARSE_APP_ID=YOUR_APPLICATION_ID
PARSE_MASTER_KEY=YOUR_MASTER_KEY
PARSE_SERVER_URL=https://YOUR_APP_ID.b4a.io
PARSE_MOUNT_PATH=/parse
NODE_ENV=production
```

### Step 4: Prepare Backend for Parse

The Flask backend needs to be refactored to use Parse Server instead of SQLAlchemy. For now, you have two options:

**Option A: Use Parse Server (Recommended)**
- Migrate your Flask app to Node.js with Parse Server
- Store data in Parse database
- Estimated time: 4-6 hours

**Option B: Keep Flask, Deploy Separately**
- Deploy Flask backend to Heroku, PythonAnywhere, or Railway
- Deploy Parse frontend to Back4App
- Use API calls between them
- Estimated time: 2-3 hours

### Step 5: Deploy Parse Cloud Code

1. In Back4App dashboard, go to Cloud Code
2. Upload the files from `/cloud` directory
3. Or push via Git:

```bash
git init
git add .
git commit -m "Initial chatRM deployment"
git remote add back4app https://git.back4app.com/YOUR_APP_ID.git
git push back4app main
```

### Step 6: Enable Web Hosting (Optional)

To host static files (HTML, CSS, JS):

1. Go to App Settings → Web Hosting
2. Enable it
3. Upload your templates and static files
4. Access at: https://YOUR_APP_ID.b4a.app

### Step 7: Configure Database

Back4App uses MongoDB by default. Your data models should map to Parse Objects:

```javascript
// Example Parse Object for Messages
const Message = Parse.Object.extend('Message');
const msg = new Message();
msg.set('content', 'Hello');
msg.set('username', 'user1');
msg.set('room_id', 'room123');
await msg.save();
```

### Step 8: Update Frontend

Modify your HTML/JS to use Parse SDK instead of Flask routes:

```javascript
// Old: Flask API call
fetch('/api/messages', {...})

// New: Parse SDK call
const query = new Parse.Query('Message');
const results = await query.find();
```

### Recommended Architecture for Back4App

```
chatRM/
├── cloud/
│   └── main.js              # Parse Cloud Code
├── public/                  # Web hosting files
│   ├── index.html
│   ├── css/
│   └── js/
├── config/
│   └── back4app.env        # Back4App config
└── package.json
```

### Database Schema for Parse

After deploying, create these classes in Back4App:

**User** (extends _User)
- username: String
- email: String
- profile_picture: File
- created_at: Date

**Room**
- name: String
- description: String
- created_by: Pointer<User>
- members: Array
- created_at: Date

**Message**
- content: String
- user: Pointer<User>
- room: Pointer<Room>
- media: Array
- reactions: Array
- created_at: Date

**Media**
- file: File
- message: Pointer<Message>
- media_type: String (image/video/audio)

**Reaction**
- emoji: String
- user: Pointer<User>
- message: Pointer<Message>

### Environment Variables on Back4App

Set these in App Settings → Environment Variables:

```
NODE_ENV=production
PARSE_MOUNT_PATH=/parse
MAX_UPLOAD_SIZE=52428800
```

### Testing Your Deployment

1. Navigate to `https://YOUR_APP_ID.b4a.io/parse`
2. Should see Parse Server response
3. Use REST API or Parse SDK for testing

### Troubleshooting

**"App ID not found"**
- Verify PARSE_APP_ID in environment variables
- Check .env file is in root directory

**"Connection timeout"**
- Ensure SERVER_URL is correct
- Check firewall/network settings
- Verify app is running on Back4App

**"Permission denied"**
- Check Master Key is correct
- Verify class permissions in Parse Dashboard

### Next Steps

1. Choose deployment architecture (Option A or B)
2. Migrate your Flask models to Parse Objects
3. Update Socket.IO to use Parse real-time features
4. Deploy and test

For more help: https://docs.back4app.com
