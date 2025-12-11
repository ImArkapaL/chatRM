// Parse Cloud Code for chatRM
// This file runs on Back4App servers

// Example cloud function - you can add more as needed
Parse.Cloud.define('hello', async (request) => {
  return 'Hello from Parse Cloud!';
});

// Validate user data before save
Parse.Cloud.beforeSave(Parse.User, async (request) => {
  const user = request.object;
  if (!user.get('username')) {
    throw new Parse.Error(Parse.Error.VALIDATION_ERROR, 'Username is required');
  }
});
