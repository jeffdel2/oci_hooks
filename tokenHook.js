const fs = require('fs');
const path = require('path');

// Cache for user roles database
let usersDb = null;

/**
 * Loads the users database from JSON file
 * @returns {Object} - Users database object
 */
function loadUsersDb() {
  if (!usersDb) {
    const dbPath = path.join(__dirname, 'users.json');
    const dbContent = fs.readFileSync(dbPath, 'utf8');
    usersDb = JSON.parse(dbContent);
  }
  return usersDb;
}

/**
 * Looks up user roles by subject
 * @param {string} subject - User subject identifier
 * @returns {Array} - Array of user roles, or empty array if not found
 */
function lookupUserRoles(subject) {
  const db = loadUsersDb();
  const user = db[subject];
  return user && user.roles ? user.roles : [];
}

/**
 * Extracts the subject from the Okta hook data
 * Tries multiple locations: Okta user ID, email/login from various sources
 * @param {Object} hookData - The hook data from Okta
 * @returns {Object} - Object with both id and login, or null values if not found
 */
function extractSubject(hookData) {
  const data = hookData.data;
  if (!data) {
    return { id: null, login: null };
  }

  // Extract Okta user ID
  let userId = null;
  if (data.context && data.context.user && data.context.user.id) {
    userId = data.context.user.id;
  } else if (data.identity && data.identity.claims && data.identity.claims.sub) {
    userId = data.identity.claims.sub;
  }

  // Extract login/email
  let login = null;
  if (data.context && data.context.user && data.context.user.profile && data.context.user.profile.login) {
    login = data.context.user.profile.login;
  } else if (data.context && data.context.session && data.context.session.login) {
    login = data.context.session.login;
  } else if (data.access && data.access.claims && data.access.claims.sub) {
    login = data.access.claims.sub;
  } else if (data.identity && data.identity.claims && data.identity.claims.login) {
    login = data.identity.claims.login;
  }

  return { id: userId, login: login };
}

/**
 * Processes Okta inline token hook requests
 * @param {Object} hookData - The hook data from Okta
 * @returns {Object} - Modified token data to return to Okta
 */
function processTokenHook(hookData) {
  // Log the incoming hook data for debugging
  console.log('Received token hook data:', JSON.stringify(hookData, null, 2));

  // Extract token data from the hook
  const { data } = hookData;
  
  if (!data) {
    throw new Error('Missing data in hook request');
  }

  // Extract subject identifiers (both ID and login)
  const subjectInfo = extractSubject(hookData);
  if (!subjectInfo.id && !subjectInfo.login) {
    console.warn('Could not extract subject from hook data');
  }

  // Try to look up roles by user ID first, then by login/email
  let roles = [];
  if (subjectInfo.id) {
    roles = lookupUserRoles(subjectInfo.id);
  }
  if (roles.length === 0 && subjectInfo.login) {
    roles = lookupUserRoles(subjectInfo.login);
  }

  console.log(`User ID: ${subjectInfo.id}, Login: ${subjectInfo.login}, Roles:`, roles);

  // Deep clone the data to avoid mutating the original
  const modifiedData = JSON.parse(JSON.stringify(data));

  // Add roles to access token claims if they exist
  if (modifiedData.access && modifiedData.access.claims) {
    modifiedData.access.claims.roles = roles;
    modifiedData.access.claims.roles_string = roles.join(' ');
  }

  // Add roles to identity token claims if they exist
  if (modifiedData.identity && modifiedData.identity.claims) {
    modifiedData.identity.claims.roles = roles;
    modifiedData.identity.claims.roles_string = roles.join(' ');
  }

  // Return the modified token data
  return {
    commands: [
      {
        type: 'com.okta.access.patch',
        value: modifiedData
      }
    ]
  };
}

module.exports = {
  processTokenHook
};

