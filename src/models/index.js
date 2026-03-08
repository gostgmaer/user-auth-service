// src/models/index.js
// Eager-loads every Mongoose model so all schemas are registered at startup.
// Import this file once (in app.js) before any route or populate call runs.
'use strict';

require('./User');
require('./Role');
require('./Permission');
require('./TokenBlacklist');
require('./LogEntry');
