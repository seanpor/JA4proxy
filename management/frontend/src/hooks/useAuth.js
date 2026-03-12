"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = void 0;
// Re-export from AuthContext so existing imports keep working
var AuthContext_1 = require("../contexts/AuthContext");
Object.defineProperty(exports, "useAuth", { enumerable: true, get: function () { return AuthContext_1.useAuth; } });
