"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.log = void 0;
/**
 * Logs a message in the console if option.debug is enabled
 * @param ctx the context
 * @param options the Options object options
 * @param msg message to log
 * @return void
 */
function log(ctx, options, msg) {
    if (options.debug) {
        console.log('ntlm-client@m0rtadelo [' + (ctx === null || ctx === void 0 ? void 0 : ctx.name) + '] ' + msg);
    }
}
exports.log = log;
